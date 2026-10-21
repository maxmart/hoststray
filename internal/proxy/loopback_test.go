package proxy

import (
	"errors"
	"net"
	"strconv"
	"testing"
	"time"

	"github.com/maxmart/hoststray/internal/certs"
)

func newOnAllInterfaces(t *testing.T, port int) *Server {
	ca, _, err := certs.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	return New(Options{CA: ca, Port: port})
}

// Another program on 127.0.0.1 must make the proxy fail to start, not
// quietly take every hostname pointed at loopback. (On macOS both binds
// succeed and the more specific one gets the connections.)
func TestStartLoopbackTaken(t *testing.T) {
	port := freePort(t)
	other, err := net.Listen("tcp4", net.JoinHostPort("127.0.0.1", strconv.Itoa(port)))
	if err != nil {
		t.Fatal(err)
	}
	defer other.Close()
	go func() { // accept and hold, like a real server
		for {
			if _, err := other.Accept(); err != nil {
				return
			}
		}
	}()
	s := newOnAllInterfaces(t, port)
	err = s.Start()
	if err == nil {
		s.Stop()
		t.Skip("this OS refused the second bind instead") // not macOS
	}
	if !errors.Is(err, ErrLoopbackTaken) {
		t.Fatalf("got %v", err)
	}
	// The failed start released the port.
	if l, err := net.Listen("tcp", ":"+strconv.Itoa(port)); err != nil {
		t.Fatalf("port still held: %v", err)
	} else {
		l.Close()
	}
}

func TestLoopbackTakenLater(t *testing.T) {
	old := loopbackCheckEvery
	loopbackCheckEvery = 100 * time.Millisecond
	defer func() { loopbackCheckEvery = old }()
	got := make(chan error, 1)
	OnLoopbackTaken = func(err error) { got <- err }
	defer func() { OnLoopbackTaken = nil }()

	port := freePort(t)
	s := newOnAllInterfaces(t, port)
	if err := s.Start(); err != nil {
		t.Fatal(err)
	}
	defer s.Stop()
	select {
	case err := <-got:
		t.Fatalf("reported while nothing else listens: %v", err)
	case <-time.After(300 * time.Millisecond):
	}
	other, err := net.Listen("tcp4", net.JoinHostPort("127.0.0.1", strconv.Itoa(port)))
	if err != nil {
		t.Skip("this OS refused the second bind:", err)
	}
	defer other.Close()
	select {
	case err := <-got:
		if !errors.Is(err, ErrLoopbackTaken) {
			t.Fatal(err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("not reported")
	}
}
