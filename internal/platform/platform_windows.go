package platform

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"
)

func systemHostsPath() string {
	root := os.Getenv("SystemRoot")
	if root == "" {
		root = `C:\Windows`
	}
	return filepath.Join(root, "System32", "drivers", "etc", "hosts")
}

// hidden runs a console program without flashing a console window.
func hidden(name string, args ...string) *exec.Cmd {
	cmd := exec.Command(name, args...)
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true, CreationFlags: windows.CREATE_NO_WINDOW}
	return cmd
}

func psQuote(s string) string { return "'" + strings.ReplaceAll(s, "'", "''") + "'" }

// runElevated runs a cmd.exe command line through a UAC prompt and waits for
// it. Declining the prompt returns ErrCancelled. Any other failure to launch
// is reported with the message PowerShell gave, rather than being mistaken
// for a decline.
func runElevated(cmdline string) error {
	script := fmt.Sprintf(`try { $p = Start-Process -FilePath cmd.exe -ArgumentList %s -Verb RunAs -Wait -PassThru -WindowStyle Hidden } catch { if (($_.Exception.NativeErrorCode -eq 1223) -or ($_.Exception.InnerException.NativeErrorCode -eq 1223)) { exit 1223 }; [Console]::Error.Write($_.Exception.Message); exit 1224 }; exit $p.ExitCode`,
		psQuote("/c "+cmdline))
	cmd := hidden("powershell.exe", "-NoProfile", "-NonInteractive", "-Command", script)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	err := cmd.Run()
	if ee, ok := err.(*exec.ExitError); ok {
		switch ee.ExitCode() {
		case 1223:
			return ErrCancelled
		case 1224:
			return fmt.Errorf("could not elevate: %s", strings.TrimSpace(stderr.String()))
		}
	}
	return err
}

func cmdQuote(s string) string { return `"` + s + `"` }

func elevatedCopy(src, dst string) error {
	return runElevated("copy /Y " + cmdQuote(src) + " " + cmdQuote(dst) + " >nul && ipconfig /flushdns >nul")
}

func setUserWritable(path string, enable bool) error {
	name, err := currentUser()
	if err != nil {
		return err
	}
	if enable {
		return runElevated("icacls " + cmdQuote(path) + " /grant " + cmdQuote(name+":(M)") + " >nul")
	}
	return runElevated("icacls " + cmdQuote(path) + " /remove:g " + cmdQuote(name) + " >nul")
}

func trustCA(certPath string) error {
	// The current user's Root store needs no admin; Windows shows its own
	// security warning asking the user to confirm.
	out, err := hidden("certutil.exe", "-user", "-addstore", "Root", certPath).CombinedOutput()
	if err != nil {
		return fmt.Errorf("%v: %s", err, strings.TrimSpace(string(out)))
	}
	return nil
}

func trustCommand(certPath string) string {
	return `certutil -user -addstore Root "` + certPath + `"`
}

var (
	user32                 = windows.NewLazySystemDLL("user32.dll")
	procMessageBox         = user32.NewProc("MessageBoxW")
	comctl32               = windows.NewLazySystemDLL("comctl32.dll")
	procTaskDialogIndirect = comctl32.NewProc("TaskDialogIndirect")
)

const (
	mbOK          = 0x0
	mbYesNoCancel = 0x3
	mbYesNo       = 0x4
	mbIconInfo    = 0x40
	mbTopmost     = 0x40000
	mbSetFg       = 0x10000
	idYes         = 6
	idNo          = 7
)

// TASKDIALOGCONFIG is declared #pragma pack(1) in commctrl.h, so it is laid
// out by hand rather than as a Go struct. Offsets are for amd64.
const (
	tdcSize       = 160
	tdcFlags      = 20
	tdcTitle      = 28
	tdcMainIcon   = 36
	tdcMainInstr  = 44
	tdcContent    = 52
	tdcCButtons   = 60
	tdcPButtons   = 64
	tdButtonSize  = 12
	tdfAllowClose = 0x0008 // TDF_ALLOW_DIALOG_CANCELLATION
	tdIconInfo    = 0xFFFD // MAKEINTRESOURCEW(-3)
	firstButtonID = 100
)

// taskDialog shows a dialog whose buttons carry their real labels. It returns
// the index of the button pressed, or -1 if the dialog was closed. It fails
// when common controls v6 isn't available (a plain `go build` exe has no
// manifest); callers fall back to MessageBox.
func taskDialog(title, message string, buttons []string) (int, error) {
	if err := procTaskDialogIndirect.Find(); err != nil {
		return 0, err
	}
	var keep []*uint16
	str := func(s string) uintptr {
		p, _ := windows.UTF16PtrFromString(s)
		keep = append(keep, p)
		return uintptr(unsafe.Pointer(p))
	}
	putPtr := func(b []byte, off int, v uintptr) { binary.LittleEndian.PutUint64(b[off:], uint64(v)) }
	putU32 := func(b []byte, off int, v uint32) { binary.LittleEndian.PutUint32(b[off:], v) }

	btns := make([]byte, tdButtonSize*len(buttons))
	for i, label := range buttons {
		putU32(btns, i*tdButtonSize, uint32(firstButtonID+i))
		putPtr(btns, i*tdButtonSize+4, str(label))
	}
	cfg := make([]byte, tdcSize)
	putU32(cfg, 0, tdcSize)
	putU32(cfg, tdcFlags, tdfAllowClose)
	putPtr(cfg, tdcTitle, str("Hosts Tray"))
	putPtr(cfg, tdcMainIcon, tdIconInfo)
	putPtr(cfg, tdcMainInstr, str(title))
	putPtr(cfg, tdcContent, str(message))
	putU32(cfg, tdcCButtons, uint32(len(buttons)))
	putPtr(cfg, tdcPButtons, uintptr(unsafe.Pointer(&btns[0])))

	var pressed int32
	hr, _, _ := procTaskDialogIndirect.Call(uintptr(unsafe.Pointer(&cfg[0])), uintptr(unsafe.Pointer(&pressed)), 0, 0)
	runtime.KeepAlive(keep)
	runtime.KeepAlive(btns)
	if hr != 0 {
		return 0, fmt.Errorf("TaskDialogIndirect: 0x%x", hr)
	}
	if i := int(pressed) - firstButtonID; i >= 0 && i < len(buttons) {
		return i, nil
	}
	return -1, nil
}

// ask shows the buttons with their own labels where it can. Closing the
// dialog returns -1.
func ask(title, message string, buttons []string) int {
	labels := buttons
	if len(labels) == 0 {
		labels = []string{"OK"}
	}
	if i, err := taskDialog(title, message, labels); err == nil {
		if len(buttons) <= 1 {
			return 0
		}
		return i
	}
	// MessageBox can't relabel its buttons, so they're named in the text.
	style := uintptr(mbOK)
	switch {
	case len(buttons) >= 3:
		style = mbYesNoCancel
		message += fmt.Sprintf("\n\nYes: %s\nNo: %s\nCancel: %s", buttons[0], buttons[1], buttons[2])
	case len(buttons) == 2:
		style = mbYesNo
		message += fmt.Sprintf("\n\nYes: %s\nNo: %s", buttons[0], buttons[1])
	}
	t, _ := windows.UTF16PtrFromString(title)
	m, _ := windows.UTF16PtrFromString(message)
	r, _, _ := procMessageBox.Call(0, uintptr(unsafe.Pointer(m)), uintptr(unsafe.Pointer(t)), style|mbIconInfo|mbTopmost|mbSetFg)
	switch {
	case len(buttons) <= 1:
		return 0
	case r == idYes:
		return 0
	case r == idNo:
		return 1
	case len(buttons) >= 3:
		return 2
	default:
		return -1
	}
}

func openURL(url string) error {
	verb, _ := windows.UTF16PtrFromString("open")
	u, _ := windows.UTF16PtrFromString(url)
	return windows.ShellExecute(0, verb, u, nil, nil, windows.SW_SHOWNORMAL)
}

func copyToClipboard(text string) error {
	cmd := hidden("cmd.exe", "/c", "clip")
	cmd.Stdin = strings.NewReader(text)
	return cmd.Run()
}

const runKey = `Software\Microsoft\Windows\CurrentVersion\Run`
const runValue = "Hosts Tray"

func loginItemEnabled() bool {
	k, err := registry.OpenKey(registry.CURRENT_USER, runKey, registry.QUERY_VALUE)
	if err != nil {
		return false
	}
	defer k.Close()
	v, _, err := k.GetStringValue(runValue)
	return err == nil && strings.EqualFold(strings.Trim(v, `"`), executable())
}

func setLoginItem(enable bool) error {
	k, err := registry.OpenKey(registry.CURRENT_USER, runKey, registry.SET_VALUE)
	if err != nil {
		return err
	}
	defer k.Close()
	if !enable {
		if err := k.DeleteValue(runValue); err != nil && err != registry.ErrNotExist {
			return err
		}
		return nil
	}
	return k.SetStringValue(runValue, `"`+executable()+`"`)
}
