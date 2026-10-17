package app

import (
	"crypto/subtle"
	"embed"
	"encoding/json"
	"errors"
	"io"
	"log"
	"net"
	"net/http"
	"strconv"

	"github.com/maxmart/hoststray/internal/hosts"
	"github.com/maxmart/hoststray/internal/platform"
	"github.com/maxmart/hoststray/internal/proxyconf"
)

//go:embed web
var webFS embed.FS

const maxBody = 4 << 20

// Handler serves the editors and the API they and agents use. It is meant for
// 127.0.0.1 only and rejects requests whose Host or Origin isn't local, so
// websites can't reach it (cross-site requests or DNS rebinding).
func (a *App) Handler() http.Handler {
	mux := http.NewServeMux()
	page := func(name string) http.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) {
			b, _ := webFS.ReadFile("web/" + name)
			w.Header().Set("Content-Type", "text/html; charset=utf-8")
			w.Header().Set("Cache-Control", "no-store")
			w.Write(b)
		}
	}
	mux.HandleFunc("GET /{$}", page("console.html"))
	// The editors used to be separate pages.
	for _, section := range []string{"hosts", "routes"} {
		mux.HandleFunc("GET /"+section, func(w http.ResponseWriter, r *http.Request) {
			http.Redirect(w, r, "/#"+section, http.StatusFound)
		})
	}
	mux.HandleFunc("GET /health", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusOK, map[string]string{"app": "hoststray", "version": a.cfg.Version})
	})

	mux.Handle("GET /api/hosts", a.authed(func(w http.ResponseWriter, r *http.Request) {
		doc, err := a.LoadHosts()
		if err != nil {
			writeErr(w, http.StatusInternalServerError, err)
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
			writeErr(w, http.StatusInternalServerError, err)
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

	// Settings, for the console only: agents can't change these.
	mux.Handle("POST /api/settings", a.authed(func(w http.ResponseWriter, r *http.Request) {
		var in struct {
			LoginItem    *bool `json:"loginItem"`
			Passwordless *bool `json:"passwordless"`
		}
		if !readJSON(w, r, &in) {
			return
		}
		var err error
		switch {
		case in.LoginItem != nil:
			err = platform.SetLoginItem(*in.LoginItem)
		case in.Passwordless != nil:
			err = a.SetHostsPasswordless(*in.Passwordless)
		default:
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": `need "loginItem" or "passwordless"`})
			return
		}
		a.changed()
		switch {
		case errors.Is(err, platform.ErrCancelled):
			writeErr(w, http.StatusConflict, err)
		case err != nil:
			writeErr(w, http.StatusInternalServerError, err)
		default:
			writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
		}
	}))
	mux.Handle("POST /api/trust", a.authed(func(w http.ResponseWriter, r *http.Request) {
		if err := a.TrustCA(); err != nil {
			writeErr(w, http.StatusInternalServerError, err)
			return
		}
		writeJSON(w, http.StatusOK, map[string]bool{"caTrusted": a.CA.Trusted()})
	}))
	mux.Handle("POST /api/skill", a.authed(func(w http.ResponseWriter, r *http.Request) {
		path, err := a.InstallSkill()
		if err != nil {
			writeErr(w, http.StatusInternalServerError, err)
			return
		}
		writeJSON(w, http.StatusOK, map[string]string{"path": path})
	}))
	mux.Handle("POST /api/updates/check", a.authed(func(w http.ResponseWriter, r *http.Request) {
		go a.CheckForUpdates(true) // reports back with its own dialogs
		writeJSON(w, http.StatusAccepted, map[string]bool{"ok": true})
	}))
	mux.Handle("POST /api/updates/install", a.authed(func(w http.ResponseWriter, r *http.Request) {
		if err := a.InstallUpdate(); err != nil {
			writeErr(w, http.StatusInternalServerError, err)
			return
		}
		writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
	}))
	mux.Handle("POST /api/open-data-folder", a.authed(func(w http.ResponseWriter, r *http.Request) {
		if err := platform.OpenURL(a.cfg.DataDir); err != nil {
			writeErr(w, http.StatusInternalServerError, err)
			return
		}
		writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
	}))

	// For agents (see skill/SKILL.md).
	mux.HandleFunc("GET /SKILL.md", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/markdown; charset=utf-8")
		io.WriteString(w, a.Skill())
	})
	mux.Handle("GET /api/status", a.agentAuthed(func(w http.ResponseWriter, r *http.Request) {
		st, err := a.Status()
		if err != nil {
			writeErr(w, http.StatusInternalServerError, err)
			return
		}
		writeJSON(w, http.StatusOK, st)
	}))
	mux.Handle("POST /api/group", a.agentAuthed(func(w http.ResponseWriter, r *http.Request) {
		var in struct {
			Name    string `json:"name"`
			Enabled *bool  `json:"enabled"`
		}
		if !readJSON(w, r, &in) {
			return
		}
		if in.Name == "" || in.Enabled == nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": `need "name" and "enabled"`})
			return
		}
		res, err := a.SetGroup(in.Name, *in.Enabled)
		switch {
		case errors.Is(err, ErrNoGroup):
			writeErr(w, http.StatusNotFound, err)
		case errors.Is(err, platform.ErrCancelled):
			writeErr(w, http.StatusConflict, err)
		case err != nil:
			writeErr(w, http.StatusInternalServerError, err)
		default:
			writeJSON(w, http.StatusOK, map[string]any{"name": in.Name, "enabled": *in.Enabled, "elevated": res.Elevated})
		}
	}))
	mux.Handle("POST /api/proxy/enabled", a.agentAuthed(func(w http.ResponseWriter, r *http.Request) {
		var in struct {
			Enabled *bool `json:"enabled"`
		}
		if !readJSON(w, r, &in) {
			return
		}
		if in.Enabled == nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": `need "enabled"`})
			return
		}
		if err := a.SetProxy(*in.Enabled); err != nil {
			writeErr(w, http.StatusInternalServerError, err)
			return
		}
		st, err := a.Status()
		if err != nil {
			writeErr(w, http.StatusInternalServerError, err)
			return
		}
		writeJSON(w, http.StatusOK, st.Proxy)
	}))

	return a.localOnly(http.NewCrossOriginProtection().Handler(mux))
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
func (a *App) authed(f http.HandlerFunc) http.Handler { return a.requireToken(f, a.token) }

// agentAuthed also accepts the agent token from the data folder. It guards
// only switching existing groups and the proxy: adding hostnames or routes
// stays with the user in the editors.
func (a *App) agentAuthed(f http.HandlerFunc) http.Handler {
	return a.requireToken(f, a.token, a.agentTok)
}

func (a *App) requireToken(f http.HandlerFunc, tokens ...string) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got := []byte(r.Header.Get("X-Hoststray-Token"))
		for _, t := range tokens {
			if subtle.ConstantTimeCompare(got, []byte(t)) == 1 {
				f(w, r)
				return
			}
		}
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "unauthorized"})
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

// ConsoleURL opens the console at a section ("", "hosts", "routes" or
// "settings"). The token rides in the fragment, which browsers never send to
// the server; the page moves it to session storage and drops it from the URL.
func (a *App) ConsoleURL(section string) string {
	return a.BaseURL() + "/#" + section + "&token=" + a.token
}

// Listen binds the admin server. It fails if another instance is running.
// Once bound, it writes the API token for agents; doing it only then keeps a
// second instance from overwriting the running one's token.
func (a *App) Listen() (net.Listener, error) {
	ln, err := net.Listen("tcp", "127.0.0.1:"+strconv.Itoa(a.cfg.AdminPort))
	if err != nil {
		return nil, err
	}
	if err := a.writeToken(); err != nil {
		log.Printf("could not write agent token: %v", err)
		if a.cfg.Interactive {
			go platform.Alert("Hosts Tray", "Coding agents won't be able to reach Hosts Tray: the token file could not be written.\n\n"+err.Error())
		}
	}
	return ln, nil
}

func (a *App) Serve(ln net.Listener) {
	srv := &http.Server{Handler: a.Handler()}
	if err := srv.Serve(ln); err != nil && err != http.ErrServerClosed {
		log.Printf("admin server stopped: %v", err)
	}
}

func writeErr(w http.ResponseWriter, code int, err error) {
	writeJSON(w, code, map[string]string{"error": err.Error()})
}
