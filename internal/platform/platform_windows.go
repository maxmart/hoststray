package platform

import (
	"crypto/sha1"
	"encoding/binary"
	"encoding/hex"
	"encoding/pem"
	"errors"
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

func systemRoot() string {
	if root := os.Getenv("SystemRoot"); root != "" {
		return root
	}
	return `C:\Windows`
}

func systemHostsPath() string {
	return filepath.Join(systemRoot(), "System32", "drivers", "etc", "hosts")
}

// hidden runs a console program without flashing a console window.
func hidden(name string, args ...string) *exec.Cmd {
	cmd := exec.Command(name, args...)
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true, CreationFlags: windows.CREATE_NO_WINDOW}
	return cmd
}

var (
	shell32            = windows.NewLazySystemDLL("shell32.dll")
	procShellExecuteEx = shell32.NewProc("ShellExecuteExW")
)

// shellExecuteInfo is SHELLEXECUTEINFOW; Go's alignment matches the C layout.
type shellExecuteInfo struct {
	cbSize     uint32
	mask       uint32
	hwnd       uintptr
	verb       *uint16
	file       *uint16
	parameters *uint16
	directory  *uint16
	show       int32
	instApp    uintptr
	idList     uintptr
	class      *uint16
	keyClass   uintptr
	hotKey     uint32
	icon       uintptr
	process    windows.Handle
}

const (
	seeMaskNoCloseProcess = 0x40
	seeMaskNoAsync        = 0x100
	seeMaskFlagNoUI       = 0x400
)

// runElevated runs a cmd.exe command line through a UAC prompt and waits for
// it. Declining the prompt returns ErrCancelled; ShellExecuteEx reports that
// as ERROR_CANCELLED, so it can't be confused with any other failure.
func runElevated(cmdline string) error {
	verb, _ := windows.UTF16PtrFromString("runas")
	file, _ := windows.UTF16PtrFromString(filepath.Join(systemRoot(), "System32", "cmd.exe"))
	params, err := windows.UTF16PtrFromString("/c " + cmdline)
	if err != nil {
		return err
	}
	info := shellExecuteInfo{mask: seeMaskNoCloseProcess | seeMaskNoAsync | seeMaskFlagNoUI,
		verb: verb, file: file, parameters: params, show: windows.SW_HIDE}
	info.cbSize = uint32(unsafe.Sizeof(info))
	if ok, _, err := procShellExecuteEx.Call(uintptr(unsafe.Pointer(&info))); ok == 0 {
		if err == windows.ERROR_CANCELLED {
			return ErrCancelled
		}
		return fmt.Errorf("could not elevate: %w", err)
	}
	if info.process == 0 {
		return errors.New("could not elevate: no process started")
	}
	defer windows.CloseHandle(info.process)
	if _, err := windows.WaitForSingleObject(info.process, windows.INFINITE); err != nil {
		return err
	}
	var code uint32
	if err := windows.GetExitCodeProcess(info.process, &code); err != nil {
		return err
	}
	if code != 0 {
		return fmt.Errorf("elevated command failed (exit code %d)", code)
	}
	return nil
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

// UntrustCA removes the CA certificate at certPath from the current user's
// Root store, if it is there; Windows asks the user to confirm. For the
// uninstaller, so it is Windows-only.
func UntrustCA(certPath string) error {
	b, err := os.ReadFile(certPath)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	} else if err != nil {
		return err
	}
	block, _ := pem.Decode(b)
	if block == nil {
		return fmt.Errorf("%s is not a PEM certificate", certPath)
	}
	sum := sha1.Sum(block.Bytes) // the store is keyed by SHA-1 thumbprint
	thumb := hex.EncodeToString(sum[:])
	if hidden("certutil.exe", "-user", "-store", "Root", thumb).Run() != nil {
		return nil // not trusted
	}
	if out, err := hidden("certutil.exe", "-user", "-delstore", "Root", thumb).CombinedOutput(); err != nil {
		return fmt.Errorf("%v: %s", err, strings.TrimSpace(string(out)))
	}
	return nil
}

var (
	user32                 = windows.NewLazySystemDLL("user32.dll")
	procMessageBox         = user32.NewProc("MessageBoxW")
	procSetWindowPos       = user32.NewProc("SetWindowPos")
	procSetForegroundWin   = user32.NewProc("SetForegroundWindow")
	comctl32               = windows.NewLazySystemDLL("comctl32.dll")
	procTaskDialogIndirect = comctl32.NewProc("TaskDialogIndirect")
)

const (
	mbOK       = 0x0
	mbYesNo    = 0x4
	mbIconInfo = 0x40
	mbTopmost  = 0x40000
	mbSetFg    = 0x10000
	idYes      = 6
	idNo       = 7
)

// TASKDIALOGCONFIG is declared #pragma pack(1) in commctrl.h, so it is laid
// out by hand rather than as a Go struct. Offsets are for 64-bit Windows.
const (
	tdcSize       = 160
	tdcFlags      = 20
	tdcTitle      = 28
	tdcMainIcon   = 36
	tdcMainInstr  = 44
	tdcContent    = 52
	tdcCButtons   = 60
	tdcPButtons   = 64
	tdcCallback   = 140
	tdButtonSize  = 12
	tdfAllowClose = 0x0008 // TDF_ALLOW_DIALOG_CANCELLATION
	tdIconInfo    = 0xFFFD // MAKEINTRESOURCEW(-3)
	tdnCreated    = 0
	firstButtonID = 100
)

// A tray app owns no foreground window, so without this its dialogs open
// behind whatever is active. MessageBox gets the same from MB_TOPMOST |
// MB_SETFOREGROUND.
var taskDialogToFront = windows.NewCallback(func(hwnd, msg, wparam, lparam, ref uintptr) uintptr {
	if msg == tdnCreated {
		const hwndTopmost = ^uintptr(0)                               // (HWND)-1
		procSetWindowPos.Call(hwnd, hwndTopmost, 0, 0, 0, 0, 0x1|0x2) // SWP_NOSIZE | SWP_NOMOVE
		procSetForegroundWin.Call(hwnd)
	}
	return 0
})

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
	putPtr(cfg, tdcCallback, taskDialogToFront)

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
	// MessageBox can't relabel its buttons, so they're named in the text. Only
	// the first two choices fit: a Cancel button would be indistinguishable
	// from closing the box.
	style := uintptr(mbOK)
	if len(buttons) >= 2 {
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
