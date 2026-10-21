package proxy

import (
	"encoding/binary"
	"net/netip"
	"path/filepath"
	"strconv"
	"unsafe"

	"golang.org/x/sys/windows"
)

var procGetExtendedTcpTable = windows.NewLazySystemDLL("iphlpapi.dll").NewProc("GetExtendedTcpTable")

const tcpTableOwnerPIDListener = 3 // TCP_TABLE_OWNER_PID_LISTENER

// listenerName names the program listening on addr. HTTP.sys, which serves
// IIS and other Windows services, shows up as the System process.
func listenerName(addr string) string {
	ap, err := netip.ParseAddrPort(addr)
	if err != nil {
		return ""
	}
	pid, ok := listenerPID(ap)
	if !ok || pid == uint32(windows.GetCurrentProcessId()) {
		return ""
	}
	if pid == 4 {
		return "System (pid 4, usually IIS or another HTTP.sys service)"
	}
	name := "pid " + strconv.Itoa(int(pid))
	h, err := windows.OpenProcess(windows.PROCESS_QUERY_LIMITED_INFORMATION, false, pid)
	if err != nil {
		return name
	}
	defer windows.CloseHandle(h)
	buf := make([]uint16, windows.MAX_PATH)
	n := uint32(len(buf))
	if windows.QueryFullProcessImageName(h, 0, &buf[0], &n) != nil {
		return name
	}
	return filepath.Base(windows.UTF16ToString(buf[:n])) + " (" + name + ")"
}

// listenerPID finds who listens on exactly ap's address and port.
func listenerPID(ap netip.AddrPort) (uint32, bool) {
	family, rowSize, addrOff, portOff, pidOff := uint32(windows.AF_INET), 24, 4, 8, 20 // MIB_TCPROW_OWNER_PID
	if ap.Addr().Is6() {
		family, rowSize, addrOff, portOff, pidOff = windows.AF_INET6, 56, 0, 20, 52 // MIB_TCP6ROW_OWNER_PID
	}
	var buf []byte
	size := uint32(0)
	for {
		var p *byte
		if len(buf) > 0 {
			p = &buf[0]
		}
		r, _, _ := procGetExtendedTcpTable.Call(uintptr(unsafe.Pointer(p)), uintptr(unsafe.Pointer(&size)), 0,
			uintptr(family), tcpTableOwnerPIDListener, 0)
		if r == uintptr(windows.ERROR_INSUFFICIENT_BUFFER) {
			buf = make([]byte, size)
			continue
		}
		if r != 0 || len(buf) < 4 {
			return 0, false
		}
		break
	}
	n := int(binary.LittleEndian.Uint32(buf))
	for i := 0; i < n; i++ {
		row := buf[4+i*rowSize:]
		if len(row) < rowSize {
			break
		}
		port := uint16(row[portOff])<<8 | uint16(row[portOff+1]) // network order
		var a netip.Addr
		if family == windows.AF_INET {
			a = netip.AddrFrom4([4]byte(row[addrOff : addrOff+4]))
		} else {
			a = netip.AddrFrom16([16]byte(row[addrOff : addrOff+16]))
		}
		if port == ap.Port() && a == ap.Addr() {
			return binary.LittleEndian.Uint32(row[pidOff:]), true
		}
	}
	return 0, false
}
