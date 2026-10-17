package app

import (
	"crypto/subtle"
	"embed"
	"encoding/json"
	"io"
	"log"
	"net"
	"net/http"
	"strconv"

	"github.com/maxmart/hoststray/internal/hosts"
	"github.com/maxmart/hoststray/internal/proxyconf"
)

//go:embed web
var webFS embed.FS

const maxBody = 4 << 20

// Handler serves the editors, their API and the MCP endpoint. It is meant for
// 127.0.0.1 only and rejects requests whose Host or Origin isn't local, so
// websites can't reach it (cross-site requests or DNS rebinding).
func (a *App) Handler() http.Handler {
	mux := http.NewServeMux()
	page := func(name string) http.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) {
			b, _ := webFS.ReadFile("web/" + name)
			w.Header().Set("Content-Type", contentType(name))
			w.Header().Set("Cache-Control", "no-store")
			w.Write(b)
		}
	}
	mux.HandleFunc("GET /{$}", func(w http.ResponseWriter, r *http.Request) { http.Redirect(w, r, "/hosts", http.StatusFound) })
	mux.HandleFunc("GET /hosts", page("editor.html"))
	mux.HandleFunc("GET /routes", page("proxy-editor.html"))
	mux.HandleFunc("GET /api.js", page("api.js"))
	mux.HandleFunc("GET /health", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusOK, map[string]string{"app": "hoststray", "version": a.cfg.Version})
	})

	mux.Handle("GET /api/hosts", a.authed(func(w http.ResponseWriter, r *http.Request) {
		doc, err := a.LoadHosts()
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
			return
		}
		writeJSON(w, http.StatusOK, doc)
	}))
	mux.Handle("POST /api/hosts", a.authed(func(w http.ResponseWriter, r *http.Request) {
		var doc hosts.Doc
		if !readJSON(w, r, &doc) {
			return
		}
		writeJSON(w, http.StatusOK, a.SaveHosts(&doc))
	}))
	mux.Handle("GET /api/proxy", a.authed(func(w http.ResponseWriter, r *http.Request) {
		cfg, err := a.LoadProxyConf()
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
			return
		}
		writeJSON(w, http.StatusOK, cfg)
	}))
	mux.Handle("POST /api/proxy", a.authed(func(w http.ResponseWriter, r *http.Request) {
		var cfg proxyconf.Config
		if !readJSON(w, r, &cfg) {
			return
		}
		writeJSON(w, http.StatusOK, a.SaveProxyConf(&cfg))
	}))

	mux.Handle("/mcp", a.mcpHandler())

	return a.localOnly(http.NewCrossOriginProtection().Handler(mux))
}

func contentType(name string) string {
	switch {
	case len(name) > 3 && name[len(name)-3:] == ".js":
		return "text/javascript; charset=utf-8"
	default:
		return "text/html; charset=utf-8"
	}
}

// localOnly rejects requests that didn't address this server by a loopback
// name (DNS rebinding) or that come from a non-local web page.
func (a *App) localOnly(next http.Handler) http.Handler {
	port := strconv.Itoa(a.cfg.AdminPort)
	allowed := map[string]bool{"127.0.0.1:" + port: true, "localhost:" + port: true, "[::1]:" + port: true}
	origins := map[string]bool{}
	for h := range allowed {
		origins["http://"+h] = true
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !allowed[r.Host] {
			http.Error(w, "forbidden host", http.StatusForbidden)
			return
		}
		if o := r.Header.Get("Origin"); o != "" && !origins[o] {
			http.Error(w, "forbidden origin", http.StatusForbidden)
			return
		}
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("X-Frame-Options", "DENY")
		next.ServeHTTP(w, r)
	})
}

// authed requires the per-launch token the tray passes to the editor pages.
func (a *App) authed(f http.HandlerFunc) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if subtle.ConstantTimeCompare([]byte(r.Header.Get("X-Hoststray-Token")), []byte(a.token)) != 1 {
			writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "unauthorized"})
			return
		}
		f(w, r)
	})
}

func readJSON(w http.ResponseWriter, r *http.Request, v any) bool {
	b, err := io.ReadAll(http.MaxBytesReader(w, r.Body, maxBody))
	if err == nil {
		err = json.Unmarshal(b, v)
	}
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"ok": false, "error": "bad request: " + err.Error()})
		return false
	}
	return true
}

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	json.NewEncoder(w).Encode(v)
}

// EditorURL is the browser URL for an editor page ("hosts" or "routes").
func (a *App) EditorURL(page string) string {
	return "http://127.0.0.1:" + strconv.Itoa(a.cfg.AdminPort) + "/" + page + "#token=" + a.token
}

// MCPURL is the endpoint agents connect to.
func (a *App) MCPURL() string { return "http://127.0.0.1:" + strconv.Itoa(a.cfg.AdminPort) + "/mcp" }

// Listen binds the admin server. It fails if another instance is running.
func (a *App) Listen() (net.Listener, error) {
	return net.Listen("tcp", "127.0.0.1:"+strconv.Itoa(a.cfg.AdminPort))
}

func (a *App) Serve(ln net.Listener) {
	srv := &http.Server{Handler: a.Handler()}
	if err := srv.Serve(ln); err != nil && err != http.ErrServerClosed {
		log.Printf("admin server stopped: %v", err)
	}
}
