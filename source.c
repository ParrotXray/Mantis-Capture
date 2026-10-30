/*
 * Receive/decode thread modules for the mantis-capture plugin.
 *
 * Structurally mirrors Suricata's own examples/plugins/ci-capture/source.c:
 * same ThreadInit/Loop/Deinit shape and tmm_modules[] wiring. What's ours
 * is the actual ring read (MantisRingPop) in place of their hardcoded
 * demo frame, ThreadInit/ThreadDeinit mmapping the inherited memfd, and a
 * real continuous loop instead of a one-shot demo.
 *
 * Data flow this replaces: XSK recv -> Bytes -> crossbeam channel ->
 * mirror thread -> sendto() -> veth -> Suricata af-packet mmap ring.
 * Becomes: XSK recv -> Bytes -> MantisRingHeader (shared memfd) -> this
 * loop -> PacketCopyData -> TmThreadsSlotProcessPkt, skipping the
 * veth/netdev/af-packet-ring hop entirely.
 */

#include "suricata.h"
#include "threadvars.h"
#include "tm-modules.h"
#include "tm-threads-common.h"
#include "tm-threads.h"
#include "packet.h"
#include "decode.h"
#include "util-debug.h"
#include "util-device.h"

#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>

#include "mantis_ring.h"
#include "source.h"

/* Names registered once via LiveRegisterDevice() in runmode.c, before any
 * thread exists; looked up per-thread via LiveGetDevice() below. Without a
 * LiveDevice, output-json.c's `if (p->livedev)` guard skips it, silently
 * losing ingress/egress attribution in EVE alerts. */
static const char *MantisLiveDevName(MantisDirection direction)
{
    return direction == MANTIS_DIR_INGRESS ? MANTIS_LIVEDEV_INGRESS : MANTIS_LIVEDEV_EGRESS;
}

typedef struct MantisThreadVars_ {
    MantisDirection direction;
    int index;
    LiveDevice *livedev;

    void *map_base;
    uint64_t map_size;
    MantisRingHeader *hdr;
    uint8_t *scratch; /* sized hdr->slot_size - 4, reused every pop */

    uint64_t pkts;
    uint64_t bytes;
    uint64_t drops;
} MantisThreadVars;

static TmEcode ReceiveMantisThreadInit(ThreadVars *tv, const void *initdata, void **data)
{
    const MantisThreadInitData *init = (const MantisThreadInitData *)initdata;
    if (init == NULL || init->ring_fd < 0) {
        SCLogError("mantis-capture: no ring fd provided to receive thread");
        return TM_ECODE_FAILED;
    }

    struct stat st;
    if (fstat(init->ring_fd, &st) != 0) {
        SCLogError("mantis-capture: fstat(%d) failed: %s", init->ring_fd, strerror(errno));
        return TM_ECODE_FAILED;
    }

    void *map = mmap(NULL, (size_t)st.st_size, PROT_READ | PROT_WRITE, MAP_SHARED, init->ring_fd, 0);
    if (map == MAP_FAILED) {
        SCLogError("mantis-capture: mmap(fd=%d, size=%" PRIu64 ") failed: %s", init->ring_fd,
                (uint64_t)st.st_size, strerror(errno));
        return TM_ECODE_FAILED;
    }

    MantisRingHeader *hdr = (MantisRingHeader *)map;
    if (!MantisRingValidate(hdr, (uint64_t)st.st_size)) {
        SCLogError("mantis-capture: ring header at fd=%d failed validation", init->ring_fd);
        munmap(map, (size_t)st.st_size);
        return TM_ECODE_FAILED;
    }

    LiveDevice *livedev = LiveGetDevice(MantisLiveDevName(init->direction));
    if (livedev == NULL) {
        SCLogError("mantis-capture: LiveGetDevice(%s) failed -- was it registered?",
                MantisLiveDevName(init->direction));
        munmap(map, (size_t)st.st_size);
        return TM_ECODE_FAILED;
    }

    MantisThreadVars *mtv = SCCalloc(1, sizeof(MantisThreadVars));
    if (mtv == NULL) {
        munmap(map, (size_t)st.st_size);
        return TM_ECODE_FAILED;
    }
    mtv->direction = init->direction;
    mtv->index = init->index;
    mtv->livedev = livedev;
    mtv->map_base = map;
    mtv->map_size = (uint64_t)st.st_size;
    mtv->hdr = hdr;
    mtv->scratch = SCMalloc(hdr->slot_size - sizeof(uint32_t));
    if (mtv->scratch == NULL) {
        munmap(map, (size_t)st.st_size);
        SCFree(mtv);
        return TM_ECODE_FAILED;
    }

    *data = mtv;
    return TM_ECODE_OK;
}

static TmEcode ReceiveMantisThreadDeinit(ThreadVars *tv, void *data)
{
    MantisThreadVars *mtv = (MantisThreadVars *)data;
    if (mtv != NULL) {
        if (mtv->map_base != NULL) {
            munmap(mtv->map_base, mtv->map_size);
        }
        SCFree(mtv->scratch);
        SCFree(mtv);
    }
    return TM_ECODE_OK;
}

static void ReceiveMantisThreadExitPrintStats(ThreadVars *tv, void *data)
{
    MantisThreadVars *mtv = (MantisThreadVars *)data;
    SCLogInfo("mantis-capture (%s #%d): pkts=%" PRIu64 " bytes=%" PRIu64 " drops=%" PRIu64,
            mtv->direction == MANTIS_DIR_INGRESS ? "ingress" : "egress", mtv->index, mtv->pkts, mtv->bytes,
            mtv->drops);
}

/* PktAcqLoop: called once by the thread-management framework, expected to
 * loop internally until engine shutdown. Checks suricata_ctl_flags &
 * SURICATA_STOP directly rather than relying on a PktAcqBreakLoop
 * callback (PktAcqBreakLoop is left NULL below). */
static TmEcode ReceiveMantisLoop(ThreadVars *tv, void *data, void *slot)
{
    MantisThreadVars *mtv = (MantisThreadVars *)data;
    TmSlot *s = ((TmSlot *)slot)->slot_next;

    TmThreadsSetFlag(tv, THV_RUNNING);

    uint32_t idle_spins = 0;

    while (!(suricata_ctl_flags & SURICATA_STOP)) {
        uint32_t len = 0;
        if (!MantisRingPop(mtv->hdr, mtv->scratch, &len)) {
            /* Empty: short backoff. A v2 could replace this with a futex
             * wait on hdr->head to avoid burning CPU while idle; v1 keeps
             * it simple to validate the rest of the pipeline first. */
            idle_spins++;
            if (idle_spins < 1000) {
                sched_yield();
            } else {
                usleep(200);
            }
            continue;
        }
        idle_spins = 0;

        PacketPoolWait();
        Packet *p = PacketGetFromQueueOrAlloc();
        if (unlikely(p == NULL)) {
            mtv->drops++;
            continue;
        }

        SCPacketSetSource(p, PKT_SRC_WIRE);
        struct timeval now;
        gettimeofday(&now, NULL);
        SCPacketSetTime(p, SCTIME_FROM_TIMEVAL(&now));
        SCPacketSetDatalink(p, LINKTYPE_ETHERNET);
        p->livedev = mtv->livedev;
        /* NOT decided yet: the egress direction reads packets at the XDP
         * hook before hardware TX checksum offload fills in the real
         * checksum, which could make Suricata flag spurious
         * checksum-invalid anomalies on otherwise-fine egress traffic. If
         * that shows up in testing, set `p->flags |= PKT_IGNORE_CHECKSUM;`
         * here, conditionally on mtv->direction == MANTIS_DIR_EGRESS. */

        if (unlikely(PacketCopyData(p, mtv->scratch, len) != 0)) {
            TmqhOutputPacketpool(tv, p);
            mtv->drops++;
            continue;
        }

        mtv->pkts++;
        mtv->bytes += len;

        if (TmThreadsSlotProcessPkt(tv, s, p) != TM_ECODE_OK) {
            return TM_ECODE_FAILED;
        }
    }

    return TM_ECODE_OK;
}

void TmModuleReceiveMantisRegister(int slot)
{
    tmm_modules[slot].name = "ReceiveMantis";
    tmm_modules[slot].ThreadInit = ReceiveMantisThreadInit;
    tmm_modules[slot].Func = NULL;
    tmm_modules[slot].PktAcqLoop = ReceiveMantisLoop;
    tmm_modules[slot].PktAcqBreakLoop = NULL;
    tmm_modules[slot].ThreadExitPrintStats = ReceiveMantisThreadExitPrintStats;
    tmm_modules[slot].ThreadDeinit = ReceiveMantisThreadDeinit;
    tmm_modules[slot].cap_flags = 0;
    tmm_modules[slot].flags = TM_FLAG_RECEIVE_TM;
}

/* --- decode side --- */

static TmEcode DecodeMantisThreadInit(ThreadVars *tv, const void *initdata, void **data)
{
    DecodeThreadVars *dtv = DecodeThreadVarsAlloc(tv);
    if (dtv == NULL) {
        return TM_ECODE_FAILED;
    }
    DecodeRegisterPerfCounters(dtv, tv);
    *data = (void *)dtv;
    return TM_ECODE_OK;
}

static TmEcode DecodeMantisThreadDeinit(ThreadVars *tv, void *data)
{
    if (data != NULL) {
        DecodeThreadVarsFree(tv, data);
    }
    return TM_ECODE_OK;
}

static TmEcode DecodeMantis(ThreadVars *tv, Packet *p, void *data)
{
    DecodeLinkLayer(tv, data, p->datalink, p, GET_PKT_DATA(p), GET_PKT_LEN(p));
    return TM_ECODE_OK;
}

void TmModuleDecodeMantisRegister(int slot)
{
    tmm_modules[slot].name = "DecodeMantis";
    tmm_modules[slot].ThreadInit = DecodeMantisThreadInit;
    tmm_modules[slot].Func = DecodeMantis;
    tmm_modules[slot].ThreadExitPrintStats = NULL;
    tmm_modules[slot].ThreadDeinit = DecodeMantisThreadDeinit;
    tmm_modules[slot].cap_flags = 0;
    tmm_modules[slot].flags = TM_FLAG_DECODE_TM;
}
