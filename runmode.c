/*
 * Runmode glue for the mantis-capture plugin.
 *
 * Two-phase startup, same pattern as Suricata's own
 * examples/plugins/ci-capture/runmode.c:
 *
 *   1. SCPluginsLoad() calls plugin->Init() (a static function in
 *      plugin.c) once during startup. That calls MantisRunModeSetArgs()
 *      to parse --capture-plugin-args into the statics below, then
 *      MantisRunModeRegister() to register a "workers" runmode via
 *      RunModeRegisterNewRunMode(). No threads exist yet at this point.
 *   2. Later, Suricata's normal runmode dispatch calls the function just
 *      registered -- RunModeWorkers() -- which is where
 *      TmThreadCreatePacketHandler actually spawns the receive/decode/
 *      flow-worker chains.
 *
 * Mantis creates one ring per (direction, AF_XDP queue_id), each fed by
 * exactly one XSK thread. RunModeWorkers() spawns one full
 * receive -> decode -> FlowWorker chain per ring, so every ring keeps a
 * single producer and a single consumer and detection scales with the
 * queue count instead of being capped at one thread per direction.
 *
 * Flow state stays correct across threads: Suricata's flow table is
 * global and hashed by 5-tuple, and Mantis's XDP RSS / flow sharding
 * already keeps a given flow on a stable queue per direction.
 *
 * Args format (ours, not a Suricata convention): a comma-separated
 * key=value list with one repeated key per ring, in queue_id order, e.g.
 * "ig_fd=12,ig_fd=13,eg_fd=14,eg_fd=15" -- the memfd numbers of the
 * ingress/egress rings, inherited by the suricata child process. The old
 * single-pair form "ig_fd=12,eg_fd=13" is the one-queue case of this.
 */

#include "suricata-common.h"
#include "runmodes.h"
#include "tm-threads.h"
#include "util-affinity.h"
#include "util-debug.h"
#include "util-device.h"

#include "runmode.h"
#include "source.h"

/* Upper bound on rings per direction; well above any realistic NIC
 * combined queue count. */
#define MANTIS_MAX_RINGS 256

static MantisThreadInitData g_ingress[MANTIS_MAX_RINGS];
static MantisThreadInitData g_egress[MANTIS_MAX_RINGS];
static int g_ingress_count = 0;
static int g_egress_count = 0;

static int MantisParseFd(const char *value, int *out)
{
    char *endptr = NULL;
    errno = 0;
    long fd = strtol(value, &endptr, 10);
    if (errno != 0 || endptr == value || *endptr != '\0' || fd < 0 || fd > INT_MAX) {
        return -1;
    }
    *out = (int)fd;
    return 0;
}

static int MantisAddRing(MantisThreadInitData *rings, int *count, MantisDirection direction, int fd)
{
    if (*count >= MANTIS_MAX_RINGS) {
        SCLogError("mantis-capture: more than %d %s rings given", MANTIS_MAX_RINGS,
                direction == MANTIS_DIR_INGRESS ? "ingress" : "egress");
        return -1;
    }
    rings[*count].ring_fd = fd;
    rings[*count].direction = direction;
    rings[*count].index = *count;
    (*count)++;
    return 0;
}

int MantisRunModeSetArgs(const char *args)
{
    if (args == NULL) {
        SCLogError("mantis-capture: --capture-plugin-args is required "
                   "(expected \"ig_fd=N[,ig_fd=N...],eg_fd=N[,eg_fd=N...]\")");
        return -1;
    }

    /* Heap copy: the arg string grows with the queue count, so a fixed
     * stack buffer could silently truncate the fd list. */
    char *buf = SCStrdup(args);
    if (buf == NULL) {
        SCLogError("mantis-capture: out of memory parsing --capture-plugin-args");
        return -1;
    }

    int rc = 0;
    char *saveptr = NULL;
    for (char *tok = strtok_r(buf, ",", &saveptr); tok != NULL; tok = strtok_r(NULL, ",", &saveptr)) {
        char *eq = strchr(tok, '=');
        if (eq == NULL) {
            continue;
        }
        *eq = '\0';
        const char *key = tok;

        int fd;
        if (strcmp(key, "ig_fd") == 0 || strcmp(key, "eg_fd") == 0) {
            if (MantisParseFd(eq + 1, &fd) != 0) {
                SCLogError("mantis-capture: invalid fd \"%s\" for %s", eq + 1, key);
                rc = -1;
                break;
            }
        } else {
            continue;
        }

        if (strcmp(key, "ig_fd") == 0) {
            rc = MantisAddRing(g_ingress, &g_ingress_count, MANTIS_DIR_INGRESS, fd);
        } else {
            rc = MantisAddRing(g_egress, &g_egress_count, MANTIS_DIR_EGRESS, fd);
        }
        if (rc != 0) {
            break;
        }
    }
    SCFree(buf);

    if (rc != 0) {
        return -1;
    }
    if (g_ingress_count == 0 || g_egress_count == 0) {
        SCLogError("mantis-capture: missing ig_fd/eg_fd in --capture-plugin-args=\"%s\"", args);
        return -1;
    }
    return 0;
}

static int SpawnMantisThread(MantisThreadInitData *initdata)
{
    /* Kept short: Suricata copies this into tv->name and uses it as the
     * pthread name, both capped at 16 bytes including the NUL. */
    char thread_name[16];
    snprintf(thread_name, sizeof(thread_name), "W#Mantis%s%02d",
            initdata->direction == MANTIS_DIR_INGRESS ? "Ig" : "Eg", initdata->index);

    ThreadVars *tv = TmThreadCreatePacketHandler(
            thread_name, "packetpool", "packetpool", "packetpool", "packetpool", "pktacqloop");
    if (tv == NULL) {
        SCLogError("mantis-capture: TmThreadCreatePacketHandler failed for %s", thread_name);
        return -1;
    }

    TmModule *tm_module = TmModuleGetByName("ReceiveMantis");
    if (tm_module == NULL) {
        FatalError("mantis-capture: TmModuleGetByName failed for ReceiveMantis");
    }
    TmSlotSetFuncAppend(tv, tm_module, initdata);

    tm_module = TmModuleGetByName("DecodeMantis");
    if (tm_module == NULL) {
        FatalError("mantis-capture: TmModuleGetByName failed for DecodeMantis");
    }
    TmSlotSetFuncAppend(tv, tm_module, NULL);

    tm_module = TmModuleGetByName("FlowWorker");
    if (tm_module == NULL) {
        FatalError("mantis-capture: TmModuleGetByName failed for FlowWorker");
    }
    TmSlotSetFuncAppend(tv, tm_module, NULL);

    TmThreadSetCPU(tv, WORKER_CPU_SET);

    if (TmThreadSpawn(tv) != TM_ECODE_OK) {
        SCLogError("mantis-capture: TmThreadSpawn failed for %s", thread_name);
        return -1;
    }
    return 0;
}

static int RunModeWorkers(void)
{
    SCLogInfo("mantis-capture: spawning %d ingress and %d egress worker threads", g_ingress_count,
            g_egress_count);
    for (int i = 0; i < g_ingress_count; i++) {
        if (SpawnMantisThread(&g_ingress[i]) != 0) {
            return -1;
        }
    }
    for (int i = 0; i < g_egress_count; i++) {
        if (SpawnMantisThread(&g_egress[i]) != 0) {
            return -1;
        }
    }
    return 0;
}

void MantisRunModeRegister(int plugin_slot)
{
    /* Must happen before any thread's ReceiveMantisThreadInit calls
     * LiveGetDevice() -- both names are #defined once in source.h so this
     * can't drift from what source.c looks up. */
    LiveRegisterDevice(MANTIS_LIVEDEV_INGRESS);
    LiveRegisterDevice(MANTIS_LIVEDEV_EGRESS);

    RunModeRegisterNewRunMode(
            plugin_slot, "workers", "One mantis-capture worker thread per ring", RunModeWorkers, NULL);
}

const char *MantisCaptureGetDefaultRunMode(void)
{
    return "workers";
}
