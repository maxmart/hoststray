package helper

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"syscall"
	"time"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/svc"
	"golang.org/x/sys/windows/svc/mgr"
)

// These run as admin, from the UAC prompt (or as the service itself).

// sidRE matches local, domain and Microsoft Entra user accounts.
var sidRE = regexp.MustCompile(`^S-1-(5-21|12-1)(-\d+){4}$`)

func ValidSID(sid string) bool { return sidRE.MatchString(sid) }

// Install writes exe (the service binary the app carries) to InstalledExe and
// runs it as a service serving sid for as long as appExe exists.
func Install(sid, appExe string, exe []byte) error {
	if !ValidSID(sid) {
		return fmt.Errorf("bad user SID %q", sid)
	}
	if !filepath.IsAbs(appExe) || strings.ContainsRune(appExe, '"') {
		return fmt.Errorf("bad app path %q", appExe)
	}
	m, err := mgr.Connect()
	if err != nil {
		return err
	}
	defer m.Disconnect()
	s, err := m.OpenService(Service)
	if err == nil {
		defer s.Close()
		stopService(s) // so its exe can be replaced
	} else {
		s = nil
	}
	if err := os.MkdirAll(Dir(), 0o755); err != nil {
		return err
	}
	// Write a new file and rename it into place.
	tmp := InstalledExe() + ".new"
	if err := os.WriteFile(tmp, exe, 0o755); err != nil {
		os.Remove(tmp)
		return err
	}
	if err := replaceFile(tmp, InstalledExe()); err != nil {
		os.Remove(tmp)
		return err
	}
	args := []string{"--service", sid, appExe}
	if s == nil {
		s, err = m.CreateService(Service, InstalledExe(), mgr.Config{
			DisplayName:  "Hosts Tray Helper",
			Description:  "Lets Hosts Tray switch hosts file groups without a UAC prompt, and reset browser connections when it does.",
			StartType:    mgr.StartAutomatic,
			ErrorControl: mgr.ErrorNormal,
		}, args...)
		if err != nil {
			return err
		}
		defer s.Close()
	} else {
		cfg, err := s.Config()
		if err != nil {
			return err
		}
		cfg.BinaryPathName = syscall.EscapeArg(InstalledExe()) + " " + strings.Join(escapeAll(args), " ")
		cfg.StartType = mgr.StartAutomatic
		if err := s.UpdateConfig(cfg); err != nil {
			return err
		}
	}
	// Restart it if it ever crashes.
	s.SetRecoveryActions([]mgr.RecoveryAction{{Type: mgr.ServiceRestart, Delay: 5 * time.Second}}, 24*60*60)
	if err := s.Start(); err != nil {
		return err
	}
	for i := 0; i < 50 && !Running(); i++ {
		time.Sleep(100 * time.Millisecond)
	}
	return nil
}

func escapeAll(args []string) []string {
	out := make([]string, len(args))
	for i, a := range args {
		out[i] = syscall.EscapeArg(a)
	}
	return out
}

// Uninstall stops and removes the service.
func Uninstall() error {
	m, err := mgr.Connect()
	if err != nil {
		return err
	}
	defer m.Disconnect()
	if s, err := m.OpenService(Service); err == nil {
		stopService(s)
		err = s.Delete()
		s.Close()
		if err != nil {
			return err
		}
	}
	for i := 0; i < 20; i++ { // the exe stays locked until the process is gone
		if err := os.RemoveAll(Dir()); err == nil {
			break
		}
		time.Sleep(250 * time.Millisecond)
	}
	return nil
}

// uninstallSelf is Uninstall from inside the service: it can't wait for
// itself to stop, so its files go at the next restart.
func uninstallSelf(sid string) error {
	m, err := mgr.Connect()
	if err != nil {
		return err
	}
	defer m.Disconnect()
	s, err := m.OpenService(Service)
	if err != nil {
		return err
	}
	err = s.Delete() // takes effect once the service has stopped
	s.Close()
	GrantWrite(sid, false) // with the app gone, nothing needs it
	for _, p := range []string{InstalledExe(), logFile(), logFile() + ".1", Dir()} {
		if name, err := windows.UTF16PtrFromString(p); err == nil {
			windows.MoveFileEx(name, nil, windows.MOVEFILE_DELAY_UNTIL_REBOOT)
		}
	}
	return err
}

// GrantWrite gives sid write access to the hosts file, or takes it away: for
// those who'd rather not be asked when editing it. Any program running as the
// user could then change it.
func GrantWrite(sid string, enable bool) error {
	if !ValidSID(sid) {
		return fmt.Errorf("bad user SID %q", sid)
	}
	args := []string{hostsPath(), "/remove:g", "*" + sid}
	if enable {
		args = []string{hostsPath(), "/grant", "*" + sid + ":(M)"}
	}
	cmd := exec.Command("icacls.exe", args...)
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true, CreationFlags: windows.CREATE_NO_WINDOW}
	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("icacls: %v: %s", err, strings.TrimSpace(string(out)))
	}
	return nil
}

func stopService(s *mgr.Service) {
	st, err := s.Control(svc.Stop)
	for i := 0; err == nil && st.State != svc.Stopped && i < 100; i++ {
		time.Sleep(100 * time.Millisecond)
		st, err = s.Query()
	}
}

func replaceFile(from, to string) error {
	f, _ := windows.UTF16PtrFromString(from)
	t, _ := windows.UTF16PtrFromString(to)
	var err error
	for i := 0; i < 20; i++ { // a stopped service's exe can stay locked for a moment
		if err = windows.MoveFileEx(f, t, windows.MOVEFILE_REPLACE_EXISTING); err == nil {
			return nil
		}
		time.Sleep(250 * time.Millisecond)
	}
	return err
}
