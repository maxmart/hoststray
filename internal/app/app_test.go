package app

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/maxmart/hoststray/internal/hosts"
	"github.com/maxmart/hoststray/internal/platform"
	"github.com/maxmart/hoststray/internal/proxyconf"
)

const hostsText = "127.0.0.1 localhost\n#==== Staging\n127.0.0.1  app.example.com\n#====\n#==== Demo\n#127.0.0.1  demo.example.com\n#====\n"

func freePort(t *testing.T) int {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	return ln.Addr().(*net.TCPAddr).Port
}

type env struct {
	app   *App
	base  string
	hosts string
}

func setup(t *testing.T) *env {
	dir := t.TempDir()
	hostsPath := filepath.Join(dir, "hosts")
	os.WriteFile(hostsPath, []byte(hostsText), 0o644)
	a, err := New(Config{Version: "test", DataDir: filepath.Join(dir, "data"), HostsPath: hostsPath,
		ProxyPort: freePort(t), ListenHost: "127.0.0.1", Timeout: 5 * time.Second, AdminPort: freePort(t)})
	if err != nil {
		t.Fatal(err)
	}
	ln, err := a.Listen()
	if err != nil {
		t.Fatal(err)
	}
	srv := &http.Server{Handler: a.Handler()}
	go srv.Serve(ln)
	t.Cleanup(func() { srv.Close(); a.Shutdown() })
	return &env{app: a, base: fmt.Sprintf("http://127.0.0.1:%d", a.cfg.AdminPort), hosts: hostsPath}
}

func (e *env) do(t *testing.T, method, path string, body any, hdr map[string]string) (int, []byte) {
	t.Helper()
	var r io.Reader
	if body != nil {
		b, _ := json.Marshal(body)
		r = bytes.NewReader(b)
	}
	req, _ := http.NewRequest(method, e.base+path, r)
	req.Header.Set("Content-Type", "application/json")
	for k, v := range hdr {
		if k == "Host" {
			req.Host = v
		} else {
			req.Header.Set(k, v)
		}
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, b
}

func TestConsolePage(t *testing.T) {
	e := setup(t)
	code, b := e.do(t, "GET", "/", nil, nil)
	if code != 200 || !strings.Contains(string(b), "<title>Hosts Tray</title>") {
		t.Fatalf("console: %d", code)
	}
	// The old editor pages now open their console section.
	noRedirect := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	for _, section := range []string{"hosts", "routes"} {
		resp, err := noRedirect.Get(e.base + "/" + section)
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		if resp.StatusCode != http.StatusFound || resp.Header.Get("Location") != "/#"+section {
			t.Errorf("/%s: %d %s", section, resp.StatusCode, resp.Header.Get("Location"))
		}
	}
	if got, want := e.app.ConsoleURL("hosts"), e.base+"/#hosts&token="+e.app.Token(); got != want {
		t.Fatalf("console URL %s, want %s", got, want)
	}
}

func TestSettingsAreEditorOnly(t *testing.T) {
	e := setup(t)
	agent, _ := os.ReadFile(e.app.TokenPath())
	for _, path := range []string{"/api/settings", "/api/trust", "/api/skill", "/api/updates/check", "/api/updates/install", "/api/open-data-folder"} {
		if code, _ := e.do(t, "POST", path, map[string]any{}, map[string]string{"X-Hoststray-Token": string(agent)}); code != 401 {
			t.Errorf("agent token on %s: %d", path, code)
		}
	}
	tok := map[string]string{"X-Hoststray-Token": e.app.Token()}
	if code, _ := e.do(t, "POST", "/api/settings", map[string]any{}, tok); code != 400 {
		t.Errorf("empty settings: %d", code)
	}
	code, b := e.do(t, "GET", "/api/status", nil, tok)
	if code != 200 || !strings.Contains(string(b), `"dataDir"`) || !strings.Contains(string(b), `"loginItem"`) {
		t.Errorf("status: %d %s", code, b)
	}
}

func TestHostsAPI(t *testing.T) {
	e := setup(t)
	tok := map[string]string{"X-Hoststray-Token": e.app.Token()}

	if code, _ := e.do(t, "GET", "/api/hosts", nil, nil); code != 401 {
		t.Fatalf("no token: %d", code)
	}
	if code, _ := e.do(t, "GET", "/api/hosts", nil, map[string]string{"X-Hoststray-Token": "nope"}); code != 401 {
		t.Fatalf("bad token: %d", code)
	}
	code, b := e.do(t, "GET", "/api/hosts", nil, tok)
	if code != 200 {
		t.Fatalf("load: %d %s", code, b)
	}
	var doc hosts.Doc
	json.Unmarshal(b, &doc)
	// Edit like the editor does: change a host and clear raw.
	doc.Nodes[1].Children[0].Host = "app2.example.com"
	doc.Nodes[1].Children[0].Raw = nil
	code, b = e.do(t, "POST", "/api/hosts", doc, tok)
	if code != 200 || !strings.Contains(string(b), `"ok":true`) {
		t.Fatalf("save: %d %s", code, b)
	}
	got, _ := os.ReadFile(e.hosts)
	if want := strings.Replace(hostsText, "127.0.0.1  app.example.com", "127.0.0.1  app2.example.com", 1); string(got) != want {
		t.Fatalf("file:\n%s", got)
	}
	if code, _ := e.do(t, "POST", "/api/hosts", "garbage", tok); code != 400 {
		t.Fatalf("bad body: %d", code)
	}
}

func TestLocalOnly(t *testing.T) {
	e := setup(t)
	tok := e.app.Token()
	// DNS rebinding: request reaches us but names another host.
	if code, _ := e.do(t, "GET", "/hosts", nil, map[string]string{"Host": "evil.example.com"}); code != 403 {
		t.Fatalf("rebinding: %d", code)
	}
	// A web page elsewhere posting to us.
	if code, _ := e.do(t, "POST", "/api/hosts", map[string]any{}, map[string]string{"Origin": "https://evil.example.com", "X-Hoststray-Token": tok}); code != 403 {
		t.Fatalf("foreign origin: %d", code)
	}
	if code, _ := e.do(t, "POST", "/api/group", map[string]any{"name": "Demo", "enabled": true}, map[string]string{"Origin": "https://evil.example.com", "X-Hoststray-Token": tok}); code != 403 {
		t.Fatalf("foreign origin on group: %d", code)
	}
	if code, _ := e.do(t, "POST", "/api/hosts", map[string]any{}, map[string]string{"Sec-Fetch-Site": "cross-site", "X-Hoststray-Token": tok}); code != 403 {
		t.Fatalf("cross-site fetch: %d", code)
	}
	// Same-origin page is fine.
	if code, _ := e.do(t, "GET", "/api/hosts", nil, map[string]string{"Origin": e.base, "Sec-Fetch-Site": "same-origin", "X-Hoststray-Token": tok}); code != 200 {
		t.Fatalf("same origin: %d", code)
	}
	if code, _ := e.do(t, "GET", "/health", nil, map[string]string{"Host": fmt.Sprintf("localhost:%d", e.app.cfg.AdminPort)}); code != 200 {
		t.Fatalf("localhost name: %d", code)
	}
}

func backend(t *testing.T, name string) int {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { fmt.Fprint(w, name) }))
	t.Cleanup(srv.Close)
	return srv.Listener.Addr().(*net.TCPAddr).Port
}

func (e *env) viaProxy(t *testing.T, host string) string {
	t.Helper()
	roots := x509.NewCertPool()
	roots.AddCert(e.app.CA.Cert())
	c := &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{RootCAs: roots},
		DialContext: func(ctx context.Context, n, _ string) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, n, fmt.Sprintf("127.0.0.1:%d", e.app.ProxyPort()))
		}}}
	resp, err := c.Get("https://" + host + "/")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	return string(b)
}

func TestProxyConfLiveReload(t *testing.T) {
	e := setup(t)
	tok := map[string]string{"X-Hoststray-Token": e.app.Token()}
	cfg := proxyconf.Parse(fmt.Sprintf("* -> :%d", backend(t, "one")))
	if res := e.app.SaveProxyConf(cfg); !res.OK {
		t.Fatal(res.Error)
	}
	if err := e.app.SetProxy(true); err != nil {
		t.Fatal(err)
	}
	if got := e.viaProxy(t, "app.example.com"); got != "one" {
		t.Fatalf("got %q", got)
	}
	// Save through the API like the routes editor; applies without restart.
	cfg = proxyconf.Parse(fmt.Sprintf("* -> :%d", backend(t, "two")))
	cfg.Nodes[0].Raw = nil
	code, b := e.do(t, "POST", "/api/proxy", cfg, tok)
	if code != 200 || strings.Contains(string(b), "restartNeeded") {
		t.Fatalf("save: %d %s", code, b)
	}
	if got := e.viaProxy(t, "app.example.com"); got != "two" {
		t.Fatalf("after save got %q", got)
	}
	if !e.app.Settings().ProxyEnabled {
		t.Fatal("proxy state not remembered")
	}
	e.app.SetProxy(false)
	if e.app.ProxyRunning() || e.app.Settings().ProxyEnabled {
		t.Fatal("proxy still on")
	}
}

func TestAgentAPI(t *testing.T) {
	e := setup(t)

	// Agents read their own token from disk; it is not the editors' token and
	// can't reach the editing endpoints.
	b, err := os.ReadFile(e.app.TokenPath())
	if err != nil || len(b) < 32 || string(b) == e.app.Token() {
		t.Fatalf("token file: %q %v", b, err)
	}
	tok := map[string]string{"X-Hoststray-Token": string(b)}
	for _, ep := range []string{"GET /api/hosts", "POST /api/hosts", "GET /api/proxy", "POST /api/proxy"} {
		method, path, _ := strings.Cut(ep, " ")
		if code, _ := e.do(t, method, path, map[string]any{}, tok); code != 401 {
			t.Fatalf("agent token on %s: %d", ep, code)
		}
	}

	code, skill := e.do(t, "GET", "/SKILL.md", nil, nil)
	if code != 200 || !strings.Contains(string(skill), e.base+"/api/group") ||
		!strings.Contains(string(skill), filepath.ToSlash(e.app.TokenPath())) || strings.Contains(string(skill), "{{") {
		t.Fatalf("skill: %d\n%s", code, skill)
	}

	if code, _ := e.do(t, "GET", "/api/status", nil, nil); code != 401 {
		t.Fatalf("status without token: %d", code)
	}
	code, b = e.do(t, "GET", "/api/status", nil, tok)
	var st Status
	json.Unmarshal(b, &st)
	if code != 200 || len(st.Groups) != 2 || st.Groups[1].Enabled {
		t.Fatalf("status: %d %s", code, b)
	}

	code, b = e.do(t, "POST", "/api/group", map[string]any{"name": "Demo", "enabled": true}, tok)
	if code != 200 || !strings.Contains(string(b), `"enabled":true`) {
		t.Fatalf("set group: %d %s", code, b)
	}
	if b, _ := os.ReadFile(e.hosts); !strings.Contains(string(b), "\n127.0.0.1  demo.example.com\n") {
		t.Fatalf("hosts not updated:\n%s", b)
	}
	if code, b := e.do(t, "POST", "/api/group", map[string]any{"name": "Nope", "enabled": true}, tok); code != 404 {
		t.Fatalf("missing group: %d %s", code, b)
	}
	if code, _ := e.do(t, "POST", "/api/group", map[string]any{"enabled": true}, tok); code != 400 {
		t.Fatalf("missing name: %d", code)
	}
	if code, _ := e.do(t, "POST", "/api/group", map[string]any{"name": "Demo"}, tok); code != 400 {
		t.Fatalf("missing enabled: %d", code)
	}

	os.WriteFile(e.app.ProxyConfPath(), []byte(fmt.Sprintf("* -> :%d", backend(t, "agent"))), 0o644)
	code, b = e.do(t, "POST", "/api/proxy/enabled", map[string]any{"enabled": true}, tok)
	if code != 200 || !strings.Contains(string(b), `"running":true`) {
		t.Fatalf("start proxy: %d %s", code, b)
	}
	if got := e.viaProxy(t, "x.test"); got != "agent" {
		t.Fatalf("proxy: %q", got)
	}
	code, b = e.do(t, "POST", "/api/proxy/enabled", map[string]any{"enabled": false}, tok)
	if code != 200 || !strings.Contains(string(b), `"running":false`) {
		t.Fatalf("stop proxy: %d %s", code, b)
	}
}

func TestInstallSkill(t *testing.T) {
	e := setup(t)
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)
	path, err := e.app.InstallSkill()
	if err != nil {
		t.Fatal(err)
	}
	if want := filepath.Join(home, ".claude", "skills", "hoststray", "SKILL.md"); path != want {
		t.Fatalf("path %s, want %s", path, want)
	}
	if b, _ := os.ReadFile(path); string(b) != e.app.Skill() {
		t.Fatal("installed skill differs")
	}
}

func TestTokenFileLifecycle(t *testing.T) {
	e := setup(t)
	path := e.app.TokenPath()
	if _, err := os.Stat(path); err != nil {
		t.Fatal("token file not written:", err)
	}
	// Another instance's token is left alone on shutdown.
	os.WriteFile(path, []byte("someone-else"), 0o600)
	e.app.removeToken()
	if b, _ := os.ReadFile(path); string(b) != "someone-else" {
		t.Fatalf("removed another instance's token: %q", b)
	}
	// Ours is removed, so agents can tell the app has stopped.
	e.app.writeToken()
	e.app.Shutdown()
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatal("token file left after shutdown:", err)
	}
}

func TestAgentAddsEntries(t *testing.T) {
	e := setup(t)
	b, _ := os.ReadFile(e.app.TokenPath())
	tok := map[string]string{"X-Hoststray-Token": string(b)}
	add := func(group string, entries ...string) (int, []byte) {
		var list []map[string]string
		for _, h := range entries {
			ip, host, _ := strings.Cut(h, " ")
			list = append(list, map[string]string{"ip": ip, "host": host})
		}
		return e.do(t, "POST", "/api/group/entries", map[string]any{"group": group, "entries": list}, tok)
	}

	for _, bad := range [][]string{{"::1 a.test"}, {"127.0.0.1 a b"}, {"127.0.0.1 -a.test"}, {"127.0.0.1 a.test\n10.0.0.1 evil.test"}} {
		if code, b := add("Agent", bad...); code != 400 {
			t.Fatalf("%q: %d %s", bad, code, b)
		}
	}
	if code, _ := add("", "127.0.0.1 a.test"); code != 400 {
		t.Fatalf("no group: %d", code)
	}
	// Without a tray there is nobody to ask.
	if code, b := add("Agent", "127.0.0.1 a.test"); code != 403 || !strings.Contains(string(b), "confirm") {
		t.Fatalf("headless: %d %s", code, b)
	}

	e.app.cfg.Interactive = true
	var asked string
	answer := 1
	askUser = func(title, msg string, buttons ...string) int { asked = msg; return answer }
	t.Cleanup(func() { askUser = platform.Ask })

	if code, b := add("Agent", "127.0.0.1 a.test"); code != 403 || !strings.Contains(asked, "a new group \"Agent\"") || !strings.Contains(asked, "127.0.0.1  a.test") {
		t.Fatalf("declined: %d %s\nasked: %s", code, b, asked)
	}
	if b, _ := os.ReadFile(e.hosts); strings.Contains(string(b), "a.test") {
		t.Fatal("written although the user said no")
	}
	answer = 0
	code, b := add("Agent", "127.0.0.1 a.test", "127.0.0.1 b.test")
	if code != 200 || !strings.Contains(string(b), `"host":"b.test"`) {
		t.Fatalf("added: %d %s", code, b)
	}
	if b, _ := os.ReadFile(e.hosts); !strings.Contains(string(b), "#==== Agent\n127.0.0.1  a.test\n127.0.0.1  b.test\n#====") {
		t.Fatalf("hosts:\n%s", b)
	}
	// Nothing new: no question, nothing written.
	asked = ""
	if code, b := add("Agent", "127.0.0.1 a.test"); code != 200 || asked != "" || !strings.Contains(string(b), `"added":[]`) {
		t.Fatalf("again: %d %s (asked %q)", code, b, asked)
	}
}
