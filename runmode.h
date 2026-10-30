#ifndef MANTIS_RUNMODE_H
#define MANTIS_RUNMODE_H

/* Parses --capture-plugin-args ("ig_fd=N[,ig_fd=N...],eg_fd=N[,eg_fd=N...]",
 * one fd per ring in queue_id order). Must be called before
 * MantisRunModeRegister. Returns 0 on success. */
int MantisRunModeSetArgs(const char *args);

/* Registers the "workers" runmode (one thread per ring) under plugin_slot. */
void MantisRunModeRegister(int plugin_slot);

const char *MantisCaptureGetDefaultRunMode(void);

#endif /* MANTIS_RUNMODE_H */
