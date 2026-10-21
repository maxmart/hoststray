package helper

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"time"

	"golang.org/x/sys/unix"
)

var (
	// InstalledExe is where install puts the daemon. Root owns it and the
	// folder, so the user can't replace what runs as root.
	InstalledExe = "/Library/PrivilegedHelperTools/" + Label
	Plist        = "/Library/LaunchDaemons/" + Label + ".plist"
	Socket       = "/var/run/" + Label + ".sock" // only root may create files in /var/run
	LogFile      = "/var/log/hoststray-helper.log"
	// serverUID is who must serve the socket; tests change it.
	serverUID = uint32(0)
)

// peerUID returns the user id of the process at the other end of c.
func peerUID(c *net.UnixConn) (uint32, error) {
	raw, err := c.SyscallConn()
	if err != nil {
		return 0, err
	}
	var cred *unix.Xucred
	var cerr error
	if err := raw.Control(func(fd uintptr) {
		cred, cerr = unix.GetsockoptXucred(int(fd), unix.SOL_LOCAL, unix.LOCAL_PEERCRED)
	}); err != nil {
		return 0, err
	}
	if cerr != nil {
		return 0, cerr
	}
	return cred.Uid, nil
}

// Call sends one request to the daemon.
func Call(req Request) (Response, error) {
	var resp Response
	c, err := net.DialTimeout("unix", Socket, time.Second)
	if err != nil {
		return resp, ErrNotRunning
	}
	defer c.Close()
	c.SetDeadline(time.Now().Add(15 * time.Second))
	// Only root can create the socket where it is, but check anyway.
	if uid, err := peerUID(c.(*net.UnixConn)); err != nil || uid != serverUID {
		return resp, errors.New("hosts helper: the socket isn't served by the helper")
	}
	if err := json.NewEncoder(c).Encode(req); err != nil {
		return resp, fmt.Errorf("hosts helper: %w", err)
	}
	if err := json.NewDecoder(c).Decode(&resp); err != nil {
		return resp, fmt.Errorf("hosts helper: %w", err)
	}
	if resp.NoGroup {
		return resp, fmt.Errorf("%w %q", ErrNoGroup, req.Group)
	}
	if resp.Error != "" {
		return resp, errors.New(resp.Error)
	}
	return resp, nil
}

// Running reports whether the daemon answers.
func Running() bool {
	_, err := Call(Request{Op: "version"})
	return err == nil
}

// Installed reports whether the daemon is installed, running or not.
func Installed() bool {
	_, err := os.Stat(Plist)
	return err == nil
}

// Differs reports whether the installed daemon isn't the one at bundled, as
// after an app update.
func Differs(bundled string) bool {
	a, err1 := fileHash(InstalledExe)
	b, err2 := fileHash(bundled)
	return err1 == nil && err2 == nil && !bytes.Equal(a, b)
}

func fileHash(p string) ([]byte, error) {
	f, err := os.Open(p)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return nil, err
	}
	return h.Sum(nil), nil
}
