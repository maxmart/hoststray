// Package proxy is the local HTTPS reverse proxy. It terminates TLS with a
// per-hostname certificate from the local CA and forwards requests (including
// websocket upgrades) to the route whose path prefix matches best.
package proxy

import (
	"context"
	"crypto/tls"
	"errors"
	"log"
	"net"
	"net/http"
	"net/http/httputil"
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
}

func New(opts Options) *Server {
	if opts.Port == 0 {
		opts.Port = 443
	}
	if opts.Timeout == 0 {
		opts.Timeout = 5 * time.Minute
	}
	s := &Server{opts: opts}
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
		ReadHeaderTimeout: 30 * time.Second,
		ErrorLog:          log.New(tlsNoiseFilter{}, "", 0),
	}
	s.srv, s.ln = srv, ln
	go func() {
		if err := srv.ServeTLS(ln, "", ""); err != nil && !errors.Is(err, http.ErrServerClosed) {
			log.Printf("proxy stopped: %v", err)
		}
	}()
	log.Printf("Proxy listening on %s", addr)
	return nil
}

func (s *Server) Stop() {
	s.mu.Lock()
	srv, ln := s.srv, s.ln
	s.srv, s.ln = nil, nil
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
