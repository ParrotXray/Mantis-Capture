/*
 * "mantis-eve" EVE filetype for the mantis-capture plugin.
 *
 * Replaces Suricata's unix_stream EVE output: instead of writing each
 * JSON record to a socket Mantis listens on, Write() pushes it into a
 * shared-memory MantisRing whose memfd Mantis created and passed in via
 * --capture-plugin-args (ev_fd=N). This is the reverse of the packet
 * rings: here the plugin is the producer and Mantis the consumer.
 *
 * Mirrors the shape of Suricata's examples/plugins/c-json-filetype.
 *
 * Concurrency: with EVE in non-threaded mode (the only mode Mantis
 * configures), Suricata calls ThreadInit once with thread_id 0 but Write
 * from every worker thread that logs. MantisRing is single-producer, so
 * all pushes are serialized behind ctx->lock. Alerts are rare compared to
 * packets, so this lock is effectively uncontended.
 *
 * A record that does not fit in one slot is dropped and counted, never
 * truncated: a truncated JSON record would just fail to parse on the
 * Mantis side. Same for a full ring -- Write must not block a worker.
 */

#include "suricata-common.h"
#include "suricata-plugin.h"
#include "output-eve.h"
#include "util-mem.h"
#include "util-debug.h"

#include <pthread.h>
#include <sys/mman.h>
#include <sys/stat.h>

#include "eve.h"
#include "mantis_ring.h"
#include "runmode.h"

typedef struct MantisEveContext_ {
    void *map_base;
    uint64_t map_size;
    MantisRingHeader *hdr;
    pthread_mutex_t lock;

    /* Protected by lock. */
    uint64_t records;
    uint64_t drops_full;
    uint64_t drops_oversize;
} MantisEveContext;

static int MantisEveInit(const SCConfNode *conf, const bool threaded, void **init_data)
{
    (void)conf;
    if (threaded) {
        SCLogError("mantis-capture: %s does not support threaded EVE output", MANTIS_EVE_FILETYPE_NAME);
        return -1;
    }

    int fd = MantisRunModeGetEventFd();
    if (fd < 0) {
        SCLogError("mantis-capture: %s needs ev_fd=N in --capture-plugin-args", MANTIS_EVE_FILETYPE_NAME);
        return -1;
    }

    struct stat st;
    if (fstat(fd, &st) != 0) {
        SCLogError("mantis-capture: fstat(ev_fd=%d) failed: %s", fd, strerror(errno));
        return -1;
    }

    void *map = mmap(NULL, (size_t)st.st_size, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
    if (map == MAP_FAILED) {
        SCLogError("mantis-capture: mmap(ev_fd=%d) failed: %s", fd, strerror(errno));
        return -1;
    }

    MantisRingHeader *hdr = (MantisRingHeader *)map;
    if (!MantisRingValidate(hdr, (uint64_t)st.st_size)) {
        SCLogError("mantis-capture: event ring header at ev_fd=%d failed validation", fd);
        munmap(map, (size_t)st.st_size);
        return -1;
    }

    MantisEveContext *ctx = SCCalloc(1, sizeof(MantisEveContext));
    if (ctx == NULL) {
        munmap(map, (size_t)st.st_size);
        return -1;
    }
    ctx->map_base = map;
    ctx->map_size = (uint64_t)st.st_size;
    ctx->hdr = hdr;
    pthread_mutex_init(&ctx->lock, NULL);

    *init_data = ctx;
    return 0;
}

static void MantisEveDeinit(void *init_data)
{
    MantisEveContext *ctx = (MantisEveContext *)init_data;
    if (ctx == NULL) {
        return;
    }
    SCLogInfo("mantis-capture (eve): records=%" PRIu64 " drops_full=%" PRIu64 " drops_oversize=%" PRIu64,
            ctx->records, ctx->drops_full, ctx->drops_oversize);
    munmap(ctx->map_base, ctx->map_size);
    pthread_mutex_destroy(&ctx->lock);
    SCFree(ctx);
}

/* No per-thread state: everything lives in the shared context. */
static int MantisEveThreadInit(const void *init_data, const ThreadId thread_id, void **thread_data)
{
    (void)init_data;
    (void)thread_id;
    *thread_data = NULL;
    return 0;
}

static void MantisEveThreadDeinit(const void *init_data, void *thread_data)
{
    (void)init_data;
    (void)thread_data;
}

static int MantisEveWrite(const char *buffer, const int buffer_len, const void *init_data, void *thread_data)
{
    (void)thread_data;
    MantisEveContext *ctx = (MantisEveContext *)init_data;
    if (buffer_len <= 0) {
        return 0;
    }

    uint32_t max_len = ctx->hdr->slot_size - (uint32_t)sizeof(uint32_t);
    pthread_mutex_lock(&ctx->lock);
    if ((uint32_t)buffer_len > max_len) {
        /* Log only the first one; the total is reported in Deinit. */
        if (ctx->drops_oversize++ == 0) {
            SCLogWarning("mantis-capture: EVE record of %d bytes exceeds event slot payload of %u bytes, "
                         "dropped (raise event_slot_size)",
                    buffer_len, max_len);
        }
    } else if (MantisRingPush(ctx->hdr, (const uint8_t *)buffer, (uint32_t)buffer_len)) {
        ctx->records++;
    } else {
        ctx->drops_full++;
    }
    pthread_mutex_unlock(&ctx->lock);
    return 0;
}

void MantisEveRegister(void)
{
    SCEveFileType *filetype = SCCalloc(1, sizeof(SCEveFileType));
    if (filetype == NULL) {
        FatalError("mantis-capture: failed to allocate EVE filetype");
    }
    filetype->name = MANTIS_EVE_FILETYPE_NAME;
    filetype->Init = MantisEveInit;
    filetype->Deinit = MantisEveDeinit;
    filetype->ThreadInit = MantisEveThreadInit;
    filetype->ThreadDeinit = MantisEveThreadDeinit;
    filetype->Write = MantisEveWrite;
    if (!SCRegisterEveFileType(filetype)) {
        FatalError("mantis-capture: failed to register EVE filetype %s", MANTIS_EVE_FILETYPE_NAME);
    }
}
