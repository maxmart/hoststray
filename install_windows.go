package main

import (
	"errors"
	"os"
	"path/filepath"
	"strings"

	"golang.org/x/sys/windows/registry"

	"github.com/maxmart/hoststray/internal/app"
	"github.com/maxmart/hoststray/internal/certs"
	"github.com/maxmart/hoststray/internal/platform"
)

// The installer (scripts/windows/installer.nsi) registers the app here.
const uninstallKey = `Software\Microsoft\Windows\CurrentVersion\Uninstall\HostsTray`

// noteInstalledVersion keeps the version shown in Installed apps current. An
// auto-update replaces the exe without running the installer, so nothing else
// would.
func noteInstalledVersion() {
	if version == "dev" {
		return
	}
	k, err := registry.OpenKey(registry.CURRENT_USER, uninstallKey, registry.QUERY_VALUE|registry.SET_VALUE)
	if err != nil {
		return
	}
	defer k.Close()
	dir, _, err := k.GetStringValue("InstallLocation")
	exe, err2 := os.Executable()
	if err != nil || err2 != nil || !strings.EqualFold(filepath.Clean(dir), filepath.Dir(exe)) {
		return // not the installed copy
	}
	k.SetStringValue("DisplayVersion", version)
}

// runUninstall undoes what Hosts Tray set up outside its own folders: Windows
// trusting its CA, and password-free access to the hosts file. The
// uninstaller runs it when the user chooses to remove settings too.
func runUninstall() int {
	cfg := app.ConfigFromEnv(version)
	var failed []string
	if err := platform.UntrustCA(certs.CAPath(filepath.Join(cfg.DataDir, "_certs"))); err != nil {
		failed = append(failed, "Stop trusting the certificate: "+err.Error())
	}
	if platform.HostsPasswordless(cfg.HostsPath) {
		if err := platform.SetUserWritable(cfg.HostsPath, false); err != nil && !errors.Is(err, platform.ErrCancelled) {
			failed = append(failed, "Remove password-free hosts access: "+err.Error())
		}
	}
	if len(failed) > 0 {
		platform.Alert("Hosts Tray", "Some cleanup didn't work:\n\n"+strings.Join(failed, "\n"))
		return 1
	}
	return 0
}
