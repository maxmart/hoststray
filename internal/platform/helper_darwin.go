package platform

import (
	"errors"
	"net/netip"
)

// TODO(mac): a launchd daemon like the Windows helper service
// (helper_windows.go): hosts writes without a password, and closing
// connections to the addresses a hostname moved away from.

var errNoHelper = errors.New("hosts helper not available")

func helperReady(path string) bool { return false }

func helperWrite(path string, content []byte, drop []netip.Addr) error { return errNoHelper }

func helperCommand(args []string) (code int, ok bool) { return 0, false }
