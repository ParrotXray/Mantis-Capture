#ifndef MANTIS_EVE_H
#define MANTIS_EVE_H

/* Name to use as `filetype:` under `outputs: - eve-log:` in suricata.yaml.
 * Must match EVE_FILETYPE_NAME in Mantis's detection/suricata/engine.rs. */
#define MANTIS_EVE_FILETYPE_NAME "mantis-eve"

/* Registers the "mantis-eve" EVE filetype. Called from the plugin's
 * top-level init so it exists before Suricata initializes its outputs. */
void MantisEveRegister(void);

#endif /* MANTIS_EVE_H */
