#ifndef MANTIS_SOURCE_H
#define MANTIS_SOURCE_H

/* LiveDevice names -- must be registered via LiveRegisterDevice() in
 * runmode.c before ReceiveMantisThreadInit (source.c) calls LiveGetDevice()
 * on them. Shared here so the two files can't drift apart. */
#define MANTIS_LIVEDEV_INGRESS "mantis-ingress"
#define MANTIS_LIVEDEV_EGRESS "mantis-egress"

typedef enum MantisDirection_ {
    MANTIS_DIR_INGRESS,
    MANTIS_DIR_EGRESS,
} MantisDirection;

/* Handed to ReceiveMantisThreadInit as `initdata`. Built by runmode.c from
 * the parsed --capture-plugin-args string, one instance per ring. */
typedef struct MantisThreadInitData_ {
    int ring_fd;
    MantisDirection direction;
    int index; /* position within its direction, i.e. Mantis's queue_id */
} MantisThreadInitData;

/* `slot` is the TmmId this module should register itself into -- passed
 * through from the recv_mod_id/decode_mod_id that SCPluginsLoad gave us. */
void TmModuleReceiveMantisRegister(int slot);
void TmModuleDecodeMantisRegister(int slot);

#endif /* MANTIS_SOURCE_H */
