package proxy

import (
	"bufio"
	"context"
	"crypto/sha1"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/maxmart/hoststray/internal/certs"
	"github.com/maxmart/hoststray/internal/proxyconf"
)

// backend answers HTTP with a JSON echo of the request, and websocket
// upgrades with an RFC 6455 echo server. name identifies which backend served.
func backend(t *testing.T, name string) *httptest.Server {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.EqualFold(r.Header.Get("Upgrade"), "websocket") {
			wsEcho(w, r, name)
			return
		}
		json.NewEncoder(w).Encode(map[string]any{"backend": name, "uri": r.URL.RequestURI(), "host": r.Host, "headers": r.Header})
	}))
	t.Cleanup(srv.Close)
	return srv
}

func wsEcho(w http.ResponseWriter, r *http.Request, name string) {
	h := sha1.Sum([]byte(r.Header.Get("Sec-WebSocket-Key") + "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"))
	conn, rw, _ := w.(http.Hijacker).Hijack()
	defer conn.Close()
	fmt.Fprintf(rw, "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: %s\r\n\r\n",
		base64.StdEncoding.EncodeToString(h[:]))
	rw.Flush()
	for {
		op, payload, err := readFrame(rw.Reader)
		if err != nil || op == 8 {
			return
		}
		writeFrame(rw.Writer, op, []byte(name+":"+string(payload)), false)
		rw.Flush()
	}
}

func readFrame(r *bufio.Reader) (byte, []byte, error) {
	var hdr [2]byte
	if _, err := io.ReadFull(r, hdr[:]); err != nil {
		return 0, nil, err
	}
	n := uint64(hdr[1] & 0x7f)
	switch n {
	case 126:
		var b [2]byte
		io.ReadFull(r, b[:])
		n = uint64(binary.BigEndian.Uint16(b[:]))
	case 127:
		var b [8]byte
		io.ReadFull(r, b[:])
		n = binary.BigEndian.Uint64(b[:])
	}
	var mask [4]byte
	masked := hdr[1]&0x80 != 0
	if masked {
		io.ReadFull(r, mask[:])
	}
	p := make([]byte, n)
	if _, err := io.ReadFull(r, p); err != nil {
		return 0, nil, err
	}
	if masked {
		for i := range p {
			p[i] ^= mask[i%4]
		}
	}
	return hdr[0] & 0x0f, p, nil
}

func writeFrame(w io.Writer, op byte, p []byte, mask bool) {
	b := []byte{0x80 | op}
	m := byte(0)
	if mask {
		m = 0x80
	}
	switch {
	case len(p) < 126:
		b = append(b, m|byte(len(p)))
	case len(p) < 65536:
		b = append(b, m|126, byte(len(p)>>8), byte(len(p)))
	default:
		b = append(b, m|127)
		b = binary.BigEndian.AppendUint64(b, uint64(len(p)))
	}
	if mask {
		key := []byte{1, 2, 3, 4}
		b = append(b, key...)
		q := make([]byte, len(p))
		for i := range p {
			q[i] = p[i] ^ key[i%4]
		}
		p = q
	}
	w.Write(append(b, p...))
}

func port(t *testing.T, s *httptest.Server) int {
	u, _ := url.Parse(s.URL)
	p, _ := strconv.Atoi(u.Port())
	return p
}

func freePort(t *testing.T) int {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	return ln.Addr().(*net.TCPAddr).Port
}

type fixture struct {
	srv    *Server
	ca     *certs.Authority
	port   int
	client *http.Client
}

func setup(t *testing.T, conf string) *fixture {
	ca, _, err := certs.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	p := freePort(t)
	s := New(Options{CA: ca, ListenHost: "127.0.0.1", Port: p, Timeout: 2 * time.Second})
	web, ws := proxyconf.Routes(proxyconf.Parse(conf), "")
	s.SetRoutes(web, ws)
	if err := s.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(s.Stop)
	roots := x509.NewCertPool()
	roots.AddCert(ca.Cert())
	// Resolve every hostname to the proxy, like a hosts file entry would.
	dialer := &net.Dialer{}
	tr := &http.Transport{
		TLSClientConfig: &tls.Config{RootCAs: roots},
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			return dialer.DialContext(ctx, network, "127.0.0.1:"+strconv.Itoa(p))
		},
	}
	return &fixture{srv: s, ca: ca, port: p, client: &http.Client{Transport: tr}}
}

func (f *fixture) get(t *testing.T, rawURL string) (int, map[string]any) {
	t.Helper()
	resp, err := f.client.Get(rawURL)
	if err != nil {
		t.Fatalf("GET %s: %v", rawURL, err)
	}
	defer resp.Body.Close()
	var body map[string]any
	b, _ := io.ReadAll(resp.Body)
	json.Unmarshal(b, &body)
	if body == nil {
		body = map[string]any{"text": string(b)}
	}
	return resp.StatusCode, body
}

func TestRoutingAndHeaders(t *testing.T) {
	a, b, ws := backend(t, "a"), backend(t, "b"), backend(t, "ws")
	f := setup(t, fmt.Sprintf("* -> :%d\nhttps://*/api -> 127.0.0.1:%d\nwss://*/socket -> :%d\n", port(t, a), port(t, b), port(t, ws)))

	code, body := f.get(t, "https://app.example.com/page?x=1")
	if code != 200 || body["backend"] != "a" || body["uri"] != "/page?x=1" || body["host"] != "app.example.com" {
		t.Fatalf("catch-all: %d %v", code, body)
	}
	h := body["headers"].(map[string]any)
	for k, v := range map[string]string{"X-Forwarded-Proto": "https", "X-Forwarded-Protocol": "https",
		"X-Forwarded-Port": strconv.Itoa(f.port), "X-Forwarded-Host": "app.example.com", "X-Forwarded-For": "127.0.0.1"} {
		if got := h[k].([]any)[0]; got != v {
			t.Errorf("%s = %v, want %v", k, got, v)
		}
	}
	if _, body := f.get(t, "https://other.test/api/users"); body["backend"] != "b" || body["uri"] != "/api/users" {
		t.Fatalf("longest prefix: %v", body)
	}
	// Plain HTTP requests under a websocket-only prefix still go to web routes.
	if _, body := f.get(t, "https://app.example.com/socket"); body["backend"] != "a" {
		t.Fatalf("ws route used for plain request: %v", body)
	}
}

func TestCertificatePerHost(t *testing.T) {
	a := backend(t, "a")
	f := setup(t, fmt.Sprintf("* -> :%d", port(t, a)))
	for _, host := range []string{"one.example.com", "two.test", "localhost"} {
		resp, err := f.client.Get("https://" + host + "/")
		if err != nil {
			t.Fatalf("%s: %v", host, err)
		}
		resp.Body.Close()
		if got := resp.TLS.PeerCertificates[0].DNSNames; len(got) != 1 || got[0] != host {
			t.Fatalf("%s got cert for %v", host, got)
		}
		if resp.ProtoMajor != 1 {
			t.Fatalf("expected HTTP/1.1, got %s", resp.Proto)
		}
	}
}

func TestWebsocket(t *testing.T) {
	a, ws := backend(t, "a"), backend(t, "ws")
	f := setup(t, fmt.Sprintf("* -> :%d\nwss://*/socket -> :%d\n", port(t, a), port(t, ws)))

	if got := wsRoundTrip(t, f, "/socket/x", "hello"); got != "ws:hello" {
		t.Fatalf("ws route: %q", got)
	}
	// No websocket route matches: falls back to the web route.
	if got := wsRoundTrip(t, f, "/live", "hi"); got != "a:hi" {
		t.Fatalf("ws fallback: %q", got)
	}
	// Large frame.
	big := strings.Repeat("x", 200000)
	if got := wsRoundTrip(t, f, "/socket", big); got != "ws:"+big {
		t.Fatalf("large frame: %d bytes", len(got))
	}
}

func wsRoundTrip(t *testing.T, f *fixture, path, msg string) string {
	t.Helper()
	roots := x509.NewCertPool()
	roots.AddCert(f.ca.Cert())
	conn, err := tls.Dial("tcp", "127.0.0.1:"+strconv.Itoa(f.port), &tls.Config{ServerName: "app.example.com", RootCAs: roots})
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	fmt.Fprintf(conn, "GET %s HTTP/1.1\r\nHost: app.example.com\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\n\r\n", path)
	br := bufio.NewReader(conn)
	resp, err := http.ReadResponse(br, nil)
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != 101 || resp.Header.Get("Sec-WebSocket-Accept") != "s3pPLMBiTxaQ9kYGzzhZRbK+xOo=" {
		t.Fatalf("handshake: %d %v", resp.StatusCode, resp.Header)
	}
	writeFrame(conn, 1, []byte(msg), true)
	conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	_, p, err := readFrame(br)
	if err != nil {
		t.Fatal(err)
	}
	return string(p)
}

func TestErrorsAndReload(t *testing.T) {
	f := setup(t, "* -> :1") // nothing listens on port 1
	if code, body := f.get(t, "https://app.example.com/"); code != 502 || !strings.Contains(body["text"].(string), "Proxy error") {
		t.Fatalf("dead backend: %d %v", code, body)
	}
	f.srv.SetRoutes(nil, nil)
	if code, body := f.get(t, "https://app.example.com/x"); code != 502 || !strings.Contains(body["text"].(string), "No matching route") {
		t.Fatalf("no route: %d %v", code, body)
	}
	// Live reload: new routes apply without restarting.
	a := backend(t, "a")
	web, ws := proxyconf.Routes(proxyconf.Parse(fmt.Sprintf("* -> :%d", port(t, a))), "")
	f.srv.SetRoutes(web, ws)
	if _, body := f.get(t, "https://app.example.com/"); body["backend"] != "a" {
		t.Fatalf("after reload: %v", body)
	}
}

func TestUpstreamTimeout(t *testing.T) {
	slow := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(4 * time.Second)
	}))
	defer slow.Close()
	f := setup(t, fmt.Sprintf("* -> :%d", port(t, slow)))
	start := time.Now()
	code, _ := f.get(t, "https://app.example.com/")
	if code != 502 || time.Since(start) > 3500*time.Millisecond {
		t.Fatalf("timeout: %d after %v", code, time.Since(start))
	}
}

func TestStartStop(t *testing.T) {
	f := setup(t, "* -> :1")
	if !f.srv.Running() {
		t.Fatal("not running")
	}
	// Second server on the same port fails with a listen error.
	other := New(Options{CA: f.ca, ListenHost: "127.0.0.1", Port: f.port})
	if err := other.Start(); err == nil {
		other.Stop()
		t.Fatal("expected port-in-use error")
	}
	f.srv.Stop()
	if f.srv.Running() {
		t.Fatal("still running")
	}
	if err := f.srv.Start(); err != nil {
		t.Fatalf("restart: %v", err)
	}
}
