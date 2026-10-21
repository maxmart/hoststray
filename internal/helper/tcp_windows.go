package helper

import (
	"encoding/binary"
	"fmt"
	"net/netip"
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"
)

var (
	iphlpapi        = windows.NewLazySystemDLL("iphlpapi.dll")
	procGetTcpTable = iphlpapi.NewProc("GetTcpTable")
	procSetTcpEntry = iphlpapi.NewProc("SetTcpEntry")
)

// tcpRow is MIB_TCPROW. Addresses and ports are in network byte order.
type tcpRow struct{ State, LocalAddr, LocalPort, RemoteAddr, RemotePort uint32 }

const (
	tcpStateEstablished = 5
	tcpStateDeleteTCB   = 12
)

// CloseConnections resets established connections to port 80 or 443 on the
// given addresses, whichever program holds them. Browsers then connect again
// and look the hostname up again, instead of reusing a keep-alive connection
// to where it used to point. Windows can only do this for IPv4, and only as
// admin.
func CloseConnections(addrs []netip.Addr) (int, error) {
	want := map[uint32]bool{}
	for _, a := range addrs {
		if a.Is4() {
			b := a.As4()
			want[binary.LittleEndian.Uint32(b[:])] = true
		}
	}
	if len(want) == 0 {
		return 0, nil
	}
	var buf []byte
	size := uint32(0)
	for {
		var p *byte
		if len(buf) > 0 {
			p = &buf[0]
		}
		r, _, _ := procGetTcpTable.Call(uintptr(unsafe.Pointer(p)), uintptr(unsafe.Pointer(&size)), 0)
		if syscall.Errno(r) == windows.ERROR_INSUFFICIENT_BUFFER {
			buf = make([]byte, size)
			continue
		}
		if r != 0 {
			return 0, fmt.Errorf("GetTcpTable: %w", syscall.Errno(r))
		}
		break
	}
	if len(buf) < 4 {
		return 0, nil
	}
	rows := unsafe.Slice((*tcpRow)(unsafe.Pointer(&buf[4])), binary.LittleEndian.Uint32(buf))
	closed := 0
	var firstErr error
	for _, row := range rows {
		port := uint16(row.RemotePort>>8&0xff | row.RemotePort&0xff<<8)
		if row.State != tcpStateEstablished || !want[row.RemoteAddr] || (port != 80 && port != 443) {
			continue
		}
		row.State = tcpStateDeleteTCB
		if r, _, _ := procSetTcpEntry.Call(uintptr(unsafe.Pointer(&row))); r != 0 {
			if firstErr == nil {
				firstErr = fmt.Errorf("SetTcpEntry: %w", syscall.Errno(r))
			}
			continue
		}
		closed++
	}
	return closed, firstErr
}
