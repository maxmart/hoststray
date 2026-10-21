package platform

import (
	"embed"
	"errors"
	"fmt"
	"log"
	"net/netip"
	"os"
	"strings"

	"golang.org/x/sys/windows"

	"github.com/maxmart/hoststray/internal/helper"
)

// The app side of the hosts helper (internal/helper). The app carries the
// service exe inside its own, so the updater keeps replacing a single file;
// installing writes it out to Program Files.
//
// Build it into helperbin first: `go generate ./...` (scripts/build-release.sh
// does this for each architecture).
//
//go:generate go build -trimpath -ldflags=-s -o helperbin/hoststray-helper.exe ../../cmd/hoststray-helper

//go:embed helperbin
var helperBin embed.FS

var errNoHelper = helper.ErrNotRunning

func bundledHelper() ([]byte, error) {
	b, err := helperBin.ReadFile("helperbin/hoststray-helper.exe")
	if err != nil {
		return nil, errors.New("this build of Hosts Tray doesn't include its helper (run go generate ./... before building)")
	}
	return b, nil
}

func helperReady(path string) bool { return IsSystemHosts(path) && helper.Running() }

// helperWrite: the helper only switches groups; anything else is written
// through the UAC prompt.
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

func helperOutdated() bool {
	b, err := bundledHelper()
	return err == nil && helper.Installed() && helper.DiffersFrom(b)
}

func currentSID() (string, error) {
	u, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		return "", err
	}
	return u.User.Sid.String(), nil
}

// setHelper installs or removes the helper through a UAC prompt, which runs
// this exe as admin (helperCommand).
func setHelper(enable bool) error {
	if enable {
		if _, err := bundledHelper(); err != nil {
			return err
		}
	}
	sid, err := currentSID()
	if err != nil {
		return err
	}
	op := "--uninstall-helper"
	if enable {
		op = "--install-helper"
	}
	return runElevatedExe(executable(), op+" "+sid)
}

// helperCommand runs the command line modes the UAC prompt and the
// uninstaller start; ok is false for any other command line.
func helperCommand(args []string) (code int, ok bool) {
	if len(args) == 0 {
		return 0, false
	}
	arg := func() string {
		if len(args) < 2 {
			return ""
		}
		return args[1]
	}
	var err error
	switch args[0] {
	case "--install-helper":
		var exe []byte
		if exe, err = bundledHelper(); err == nil {
			err = helper.Install(arg(), executable(), exe)
		}
	case "--uninstall-helper":
		err = helper.Uninstall()
	case "--remove-helper": // the uninstaller: prompts only if there is one
		if helper.Installed() {
			err = setHelper(false)
		}
	case "--copy-hosts": // <src> <dst> <addresses to drop connections to>
		if len(args) < 4 {
			err = errors.New("usage: --copy-hosts <src> <dst> <addresses>")
			break
		}
		err = copyHosts(args[1], args[2], args[3])
	case "--set-writable": // <path> <user SID> on|off
		if len(args) < 4 || !helper.ValidSID(args[2]) {
			err = errors.New("usage: --set-writable <path> <user SID> on|off")
			break
		}
		grant := []string{args[1], "/remove:g", "*" + args[2]}
		if args[3] == "on" {
			grant = []string{args[1], "/grant", "*" + args[2] + ":(M)"}
		}
		if out, e := hidden("icacls.exe", grant...).CombinedOutput(); e != nil {
			err = fmt.Errorf("icacls: %v: %s", e, strings.TrimSpace(string(out)))
		}
	case "--close-connections":
		err = closeConnections(arg())
	default:
		return 0, false
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1, true
	}
	return 0, true
}

// copyHosts is the UAC fallback for saving the hosts file: it overwrites dst
// in place (keeping its permissions), flushes the DNS cache and drops the
// browsers' connections to the addresses that moved.
func copyHosts(src, dst, addrs string) error {
	data, err := os.ReadFile(src)
	if err != nil {
		return err
	}
	if err := os.WriteFile(dst, data, 0o644); err != nil {
		return err
	}
	procDnsFlushResolverCache.Call()
	return closeConnections(addrs)
}

var procDnsFlushResolverCache = windows.NewLazySystemDLL("dnsapi.dll").NewProc("DnsFlushResolverCache")

// closeConnections takes a comma-separated address list.
func closeConnections(list string) error {
	var addrs []netip.Addr
	for _, s := range strings.Split(list, ",") {
		if a, err := netip.ParseAddr(s); err == nil {
			addrs = append(addrs, a)
		}
	}
	if len(addrs) == 0 {
		return nil
	}
	_, err := helper.CloseConnections(helper.Droppable(addrs))
	return err
}
