package platform

import (
	"errors"
	"log"
	"net/netip"
	"os"
	"path/filepath"
	"strconv"

	"github.com/maxmart/hoststray/internal/helper"
)

// The app side of the hosts helper (internal/helper). The helper binary ships
// next to the app's own, in Contents/MacOS.

var errNoHelper = helper.ErrNotRunning

func bundledHelper() string { return filepath.Join(filepath.Dir(executable()), "hoststray-helper") }

func helperReady(path string) bool { return IsSystemHosts(path) && helper.Running() }

// helperWrite: the helper only switches groups; anything else is written
// through the password prompt.
func helperWrite(path string, content []byte, drop []netip.Addr) error { return errNoHelper }

func helperSetGroup(path, name string, enable bool) (bool, error) {
	if !IsSystemHosts(path) {
		return false, nil
	}
	_, err := helper.Call(helper.Request{Op: "group", Group: name, Enable: enable})
	switch {
	case err == nil, errors.Is(err, helper.ErrNoGroup):
		return true, err
	case errors.Is(err, helper.ErrNotRunning):
		return false, nil
	}
	log.Printf("%v; writing without the helper", err)
	return false, nil
}

// setHelper installs or removes the helper through the admin password prompt.
// Both run the helper that ships with the app, as root.
func setHelper(enable bool) error {
	if _, err := os.Stat(bundledHelper()); err != nil {
		return errors.New("hoststray-helper is missing from the app; reinstall Hosts Tray")
	}
	uid := strconv.Itoa(os.Getuid())
	if enable {
		return runAsAdmin("Hosts Tray wants to let you switch hosts groups without a password.",
			bundledHelper(), "--install", uid, executable())
	}
	return runAsAdmin("Hosts Tray wants to ask for your password when switching groups again.",
		bundledHelper(), "--uninstall", uid)
}

func helperOutdated() bool { return helper.Installed() && helper.Differs(bundledHelper()) }

func helperCommand(args []string) (code int, ok bool) { return 0, false }
