package main

import (
	"os"
	"runtime"
	"sync"
	"unsafe"

	"golang.org/x/sys/windows"
)

// Windows closes a menu on every click. To let several switches be flipped in
// a row, reopenMenu asks systray to show the menu again, and a WinEvent hook
// puts it back where the previous one was instead of at the cursor.

var (
	user32                   = windows.NewLazySystemDLL("user32.dll")
	procFindWindowExW        = user32.NewProc("FindWindowExW")
	procGetWindowThreadPID   = user32.NewProc("GetWindowThreadProcessId")
	procPostMessageW         = user32.NewProc("PostMessageW")
	procSetWinEventHook      = user32.NewProc("SetWinEventHook")
	procGetMessageW          = user32.NewProc("GetMessageW")
	procGetWindowRect        = user32.NewProc("GetWindowRect")
	procSetWindowPos         = user32.NewProc("SetWindowPos")
	systrayClass, _          = windows.UTF16PtrFromString("SystrayClass") // fyne.io/systray's window
	menuMu                   sync.Mutex
	menuDepth                int  // open popups: 1 is the tray menu, more are submenus
	menuRect                 rect // where the tray menu last opened
	menuSeen, menuReposition bool
)

type rect struct{ Left, Top, Right, Bottom int32 }

const (
	eventMenuPopupStart = 0x0006
	eventMenuPopupEnd   = 0x0007
	wmSystray           = 0x0400 + 1 // WM_USER+1, systray's notify-icon message
	wmRButtonUp         = 0x0205
)

// watchMenu records where the tray menu opens. Call it once.
func watchMenu() {
	go func() {
		runtime.LockOSThread() // out-of-context hooks are delivered to this thread's message loop
		cb := windows.NewCallback(func(hook, event, hwnd, idObject, idChild, thread, time uintptr) uintptr {
			menuEvent(uint32(event), hwnd)
			return 0
		})
		if h, _, _ := procSetWinEventHook.Call(eventMenuPopupStart, eventMenuPopupEnd, 0, cb, uintptr(os.Getpid()), 0, 0); h == 0 {
			return
		}
		var msg [48]byte
		for {
			if r, _, _ := procGetMessageW.Call(uintptr(unsafe.Pointer(&msg[0])), 0, 0, 0); int32(r) <= 0 {
				return
			}
		}
	}()
}

func menuEvent(event uint32, hwnd uintptr) {
	menuMu.Lock()
	defer menuMu.Unlock()
	switch event {
	case eventMenuPopupStart:
		menuDepth++
		if menuDepth != 1 {
			return
		}
		var r rect
		procGetWindowRect.Call(hwnd, uintptr(unsafe.Pointer(&r)))
		if menuReposition && menuSeen {
			// Keep the bottom-left corner: the menu grows upwards from the tray.
			const swpNoSize, swpNoZOrder, swpNoActivate = 0x1, 0x4, 0x10
			x, y := menuRect.Left, menuRect.Bottom-(r.Bottom-r.Top)
			procSetWindowPos.Call(hwnd, 0, uintptr(x), uintptr(y), 0, 0, swpNoSize|swpNoZOrder|swpNoActivate)
			r = rect{x, y, x + r.Right - r.Left, menuRect.Bottom}
		}
		menuReposition = false
		menuRect, menuSeen = r, true
	case eventMenuPopupEnd:
		if menuDepth > 0 {
			menuDepth--
		}
	}
}

// reopenMenu shows the tray menu again, where it was last open.
func reopenMenu() {
	pid := uint32(os.Getpid())
	var hwnd uintptr
	for {
		hwnd, _, _ = procFindWindowExW.Call(0, hwnd, uintptr(unsafe.Pointer(systrayClass)), 0)
		if hwnd == 0 {
			return
		}
		var owner uint32
		procGetWindowThreadPID.Call(hwnd, uintptr(unsafe.Pointer(&owner)))
		if owner == pid {
			break
		}
	}
	menuMu.Lock()
	menuReposition = true
	menuMu.Unlock()
	procPostMessageW.Call(hwnd, wmSystray, 0, wmRButtonUp)
}
