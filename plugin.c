/*
 * Entry point for the mantis-capture Suricata plugin.
 *
 * Mirrors examples/plugins/ci-capture/plugin.c from suricata-8.0.6 -- the
 * version this plugin targets.
 */

#include "suricata-plugin.h"
#include "suricata-common.h"
#include "util-debug.h"

#include "eve.h"
#include "runmode.h"
#include "source.h"

static void MantisPluginInit(const char *args, int plugin_slot, int receive_slot, int decode_slot)
{
    if (MantisRunModeSetArgs(args) != 0) {
        FatalError("mantis-capture: invalid --capture-plugin-args");
    }
    MantisRunModeRegister(plugin_slot);
    TmModuleReceiveMantisRegister(receive_slot);
    TmModuleDecodeMantisRegister(decode_slot);
}

static void SCPluginInit(void)
{
    SCCapturePlugin *plugin = SCCalloc(1, sizeof(SCCapturePlugin));
    if (plugin == NULL) {
        FatalError("Failed to allocate memory for mantis-capture plugin registration");
    }
    plugin->name = "mantis-capture";
    plugin->Init = MantisPluginInit;
    plugin->GetDefaultMode = MantisCaptureGetDefaultRunMode;
    SCPluginRegisterCapture(plugin);

    /* Registered unconditionally so it already exists when Suricata sets
     * up its EVE outputs; it only needs ev_fd once actually selected via
     * `filetype: mantis-eve`. */
    MantisEveRegister();
}

const SCPlugin PluginRegistration = {
    .version = SC_API_VERSION,
    .suricata_version = SC_PACKAGE_VERSION,
    .name = "mantis-capture",
    .plugin_version = "0.1.0",
    .author = "Mantis",
    .license = "GPL-2.0-only",
    .Init = SCPluginInit,
};

const SCPlugin *SCPluginRegister(void)
{
    return &PluginRegistration;
}
