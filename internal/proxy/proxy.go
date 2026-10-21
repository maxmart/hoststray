// Package proxy is the local HTTPS reverse proxy. It terminates TLS with a
// per-hostname certificate from the local CA and forwards requests (including
// websocket upgrades) to the route whose path prefix matches best.
package proxy

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"log"
	"net"
	"net/http"
	"net/http/httputil"
	"net/netip"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/maxmart/hoststray/internal/certs"
	"github.com/maxmart/hoststray/internal/proxyconf"
)

type Options struct {
	CA         *certs.Authority
	ListenHost string        // "" = all interfaces
	Port       int           // default 443
	Timeout    time.Duration // upstream timeout, default 5 minutes
}

type route struct {
	proxyconf.Route
	rp *httputil.ReverseProxy
}

type routeSet struct{ web, ws []*route }

type Server struct {
	opts      Options
	transport *http.Transport
	routes    atomic.Pointer[routeSet]

	mu  sync.Mutex
	srv *http.Server
	ln  net.Listener

	connMu   sync.Mutex
	conns    map[net.Conn]*clientConn // browser connections, until closed or hijacked
	gen      int                      // bumped by DropKeepAlives
	accepted sync.Map                 // remote addresses of open connections, for owns
	watching chan struct{}            // closed by Stop, to end watchLoopback
}

type clientConn struct {
	gen  int // the DropKeepAlives generation it was accepted in
	idle bool
}

func New(opts Options) *Server {
	if opts.Port == 0 {
		opts.Port = 443
	}
	if opts.Timeout == 0 {
		opts.Timeout = 5 * time.Minute
	}
	s := &Server{opts: opts, conns: map[net.Conn]*clientConn{}}
	s.transport = &http.Transport{
		Proxy:                 nil, // never send local traffic through a system proxy
		DialContext:           (&net.Dialer{Timeout: 30 * time.Second, KeepAlive: 30 * time.Second}).DialContext,
		ResponseHeaderTimeout: opts.Timeout,
		MaxIdleConnsPerHost:   32,
		IdleConnTimeout:       90 * time.Second,
	}
	s.routes.Store(&routeSet{})
	return s
}

func (s *Server) Port() int { return s.opts.Port }

// SetRoutes replaces the routing table; it applies to new requests immediately.
func (s *Server) SetRoutes(web, ws []proxyconf.Route) {
	set := &routeSet{}
	for _, r := range web {
		set.web = append(set.web, s.makeRoute(r))
	}
	for _, r := range ws {
		set.ws = append(set.ws, s.makeRoute(r))
	}
	s.routes.Store(set)
}

func (s *Server) makeRoute(r proxyconf.Route) *route {
	target := &url.URL{Scheme: "http", Host: net.JoinHostPort(r.Host, strconv.Itoa(r.Port))}
	port := strconv.Itoa(s.opts.Port)
	rp := &httputil.ReverseProxy{
		Rewrite: func(pr *httputil.ProxyRequest) {
			pr.SetURL(target)
			pr.Out.Host = pr.In.Host // keep the original Host, like http-proxy did
			pr.SetXForwarded()       // X-Forwarded-For/-Host/-Proto (https)
			pr.Out.Header.Set("X-Forwarded-Protocol", "https")
			pr.Out.Header.Set("X-Forwarded-Port", port)
		},
		Transport: s.transport,
		ErrorHandler: func(w http.ResponseWriter, req *http.Request, err error) {
			log.Printf("proxy error for %s%s -> %s: %v", req.Host, req.URL.RequestURI(), target.Host, err)
			http.Error(w, "Proxy error.\n\n"+err.Error(), http.StatusBadGateway)
		},
	}
	return &route{Route: r, rp: rp}
}

// pick returns the route whose path prefix is the longest match for uri. An
// empty prefix ("*") matches everything and acts as the catch-all.
func pick(list []*route, uri string) *route {
	var best *route
	for _, r := range list {
		if strings.HasPrefix(uri, r.PathPrefix) && (best == nil || len(r.PathPrefix) > len(best.PathPrefix)) {
			best = r
		}
	}
	return best
}

func isUpgrade(r *http.Request) bool {
	return r.Header.Get("Upgrade") != "" &&
		strings.Contains(strings.ToLower(r.Header.Get("Connection")), "upgrade")
}

func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	set := s.routes.Load()
	uri := r.URL.RequestURI()
	var rt *route
	if isUpgrade(r) {
		log.Printf("Websocket: %s https://%s%s", r.Method, r.Host, uri)
		// websocket routes first; fall back to web routes so a plain "* -> :80"
		// also carries the app's own websockets.
		if rt = pick(set.ws, uri); rt == nil {
			rt = pick(set.web, uri)
		}
	} else {
		log.Printf("%s https://%s%s", r.Method, r.Host, uri)
		rt = pick(set.web, uri)
	}
	if rt == nil {
		http.Error(w, "No matching route in proxy.conf for "+uri, http.StatusBadGateway)
		return
	}
	rt.rp.ServeHTTP(w, r)
}

// Start listens and serves in the background. Listen errors (port in use, no
// permission) are returned directly.
func (s *Server) Start() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.srv != nil {
		return nil
	}
	addr := net.JoinHostPort(s.opts.ListenHost, strconv.Itoa(s.opts.Port))
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return err
	}
	srv := &http.Server{
		Handler: s,
		TLSConfig: &tls.Config{
			GetCertificate: s.opts.CA.GetCertificate,
			NextProtos:     []string{"http/1.1"}, // websockets are proxied over HTTP/1.1
			MinVersion:     tls.VersionTLS12,
		},
		TLSNextProto:      map[string]func(*http.Server, *tls.Conn, http.Handler){}, // no HTTP/2
		ConnState:         s.connState,
		ReadHeaderTimeout: 30 * time.Second,
		ErrorLog:          log.New(tlsNoiseFilter{}, "", 0),
	}
	s.srv, s.ln = srv, ln
	go func() {
		if err := srv.ServeTLS(ln, "", ""); err != nil && !errors.Is(err, http.ErrServerClosed) {
			log.Printf("proxy stopped: %v", err)
		}
	}()
	if err := s.checkLoopback(); err != nil {
		srv.Close()
		ln.Close()
		s.srv, s.ln = nil, nil
		return err
	}
	s.watching = make(chan struct{})
	go s.watchLoopback(s.watching)
	log.Printf("Proxy listening on %s", addr)
	return nil
}

// ErrLoopbackTaken means another program answers on the proxy's port at a
// loopback address, so hostnames pointed there wouldn't reach the proxy.
var ErrLoopbackTaken = errors.New("another program is listening there")

// checkLoopback makes sure connections to 127.0.0.1 and ::1 reach this
// proxy. On macOS another program can listen on 127.0.0.1:443 alongside our
// *:443 without either getting an error, and the more specific one wins. (A
// normal app can't bind 127.0.0.1 itself on a port below 1024; only root can.)
func (s *Server) checkLoopback() error {
	if s.opts.ListenHost != "" && !isLoopback(s.opts.ListenHost) {
		return nil
	}
	port := strconv.Itoa(s.opts.Port)
	for _, host := range []string{"127.0.0.1", "::1"} {
		addr := net.JoinHostPort(host, port)
		ok, err := s.owns(addr)
		if err != nil {
			continue // nothing listens there (no IPv6, or ListenHost is the other one)
		}
		if !ok {
			msg := fmt.Sprintf("%s: %v", addr, ErrLoopbackTaken)
			if name := listenerName(addr); name != "" {
				msg = fmt.Sprintf("%s: %s is listening there", addr, name)
			}
			return fmt.Errorf("%s (%w)", msg, ErrLoopbackTaken)
		}
	}
	return nil
}

func isLoopback(host string) bool {
	ip := net.ParseIP(host)
	return host == "localhost" || (ip != nil && ip.IsLoopback())
}

// owns reports whether a connection to addr arrives here.
func (s *Server) owns(addr string) (bool, error) {
	c, err := net.DialTimeout("tcp", addr, time.Second)
	if err != nil {
		return false, err
	}
	defer c.Close()
	key := addrKey(c.LocalAddr())
	for i := 0; i < 20; i++ {
		if _, ok := s.accepted.Load(key); ok {
			return true, nil
		}
		time.Sleep(25 * time.Millisecond)
	}
	return false, nil
}

func addrKey(a net.Addr) string {
	if ap, err := netip.ParseAddrPort(a.String()); err == nil {
		return netip.AddrPortFrom(ap.Addr().Unmap(), ap.Port()).String()
	}
	return a.String()
}

var loopbackCheckEvery = 30 * time.Second

// OnLoopbackTaken, if set, is called when another program starts answering
// on a loopback address while the proxy runs.
var OnLoopbackTaken func(error)

func (s *Server) watchLoopback(stop chan struct{}) {
	t := time.NewTicker(loopbackCheckEvery)
	defer t.Stop()
	reported := false
	for {
		select {
		case <-stop:
			return
		case <-t.C:
		}
		err := s.checkLoopback()
		if err != nil && !reported {
			log.Printf("proxy: %v", err)
			if OnLoopbackTaken != nil {
				OnLoopbackTaken(err)
			}
		}
		reported = err != nil
	}
}

func (s *Server) Stop() {
	s.mu.Lock()
	srv, ln := s.srv, s.ln
	s.srv, s.ln = nil, nil
	if s.watching != nil {
		close(s.watching)
		s.watching = nil
	}
	s.mu.Unlock()
	if srv == nil {
		return
	}
	// Shutdown only closes listeners Serve has registered; if the serving
	// goroutine hasn't got that far, the port would stay bound until it does.
	defer ln.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	if err := srv.Shutdown(ctx); err != nil {
		srv.Close() // websockets don't drain; cut them
	}
	s.transport.CloseIdleConnections()
}

// DropKeepAlives closes the browsers' keep-alive connections, idle ones now and
// busy ones when their request is done. Browsers reuse an open HTTP/1.1
// connection without looking at the hosts file, so after a group is turned
// off they would keep coming here instead of going to the real server.
// Websockets are left alone.
func (s *Server) DropKeepAlives() {
	s.connMu.Lock()
	s.gen++
	var idle []net.Conn
	for c, cc := range s.conns {
		if cc.idle {
			idle = append(idle, c)
			delete(s.conns, c)
		}
	}
	s.connMu.Unlock()
	for _, c := range idle {
		c.Close()
	}
}

func (s *Server) connState(c net.Conn, state http.ConnState) {
	s.connMu.Lock()
	cc := s.conns[c]
	stale := false
	switch state {
	case http.StateNew:
		s.conns[c] = &clientConn{gen: s.gen}
		s.accepted.Store(addrKey(c.RemoteAddr()), true)
	case http.StateActive:
		if cc != nil {
			cc.idle = false
		}
	case http.StateIdle:
		if cc != nil {
			cc.idle = true
			if stale = cc.gen < s.gen; stale {
				delete(s.conns, c)
			}
		}
	case http.StateHijacked, http.StateClosed:
		delete(s.conns, c)
		s.accepted.Delete(addrKey(c.RemoteAddr()))
	}
	s.connMu.Unlock()
	if stale {
		c.Close()
	}
}

func (s *Server) Running() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.srv != nil
}

// tlsNoiseFilter drops the handshake errors browsers cause routinely (e.g.
// closing a connection while showing a certificate warning).
type tlsNoiseFilter struct{}

func (tlsNoiseFilter) Write(p []byte) (int, error) {
	if !strings.Contains(string(p), "TLS handshake error") {
		log.Print(strings.TrimSuffix(string(p), "\n"))
	}
	return len(p), nil
}
