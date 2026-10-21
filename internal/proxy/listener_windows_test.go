package proxy

import (
	"net"
	"net/netip"
	"os"
	"testing"
)

func TestListenerPID(t *testing.T) {
	for _, addr := range []string{"127.0.0.1:0", "[::1]:0"} {
		l, err := net.Listen("tcp", addr)
		if err != nil {
			t.Logf("%s: %v", addr, err)
			continue
		}
		ap := netip.MustParseAddrPort(l.Addr().String())
		if pid, ok := listenerPID(ap); !ok || pid != uint32(os.Getpid()) {
			t.Errorf("%s: pid %d %v, want %d", ap, pid, ok, os.Getpid())
		}
		l.Close()
	}
	if name := listenerName("127.0.0.1:1"); name != "" {
		t.Errorf("nothing on port 1, got %q", name)
	}
}
