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
	"github.com/maxmart/hoststray/internal/proxyconf"
	"github.com/modelcontextprotocol/go-sdk/mcp"
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

func TestEditorPages(t *testing.T) {
	e := setup(t)
	for path, want := range map[string]string{"/hosts": "Hosts Tray — Editor", "/routes": "Proxy Routes", "/api.js": "window.hostsAPI"} {
		code, b := e.do(t, "GET", path, nil, nil)
		if code != 200 || !strings.Contains(string(b), want) {
			t.Errorf("%s: %d", path, code)
		}
	}
	if !strings.Contains(e.app.EditorURL("hosts"), "/hosts#token="+e.app.Token()) {
		t.Fatal(e.app.EditorURL("hosts"))
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
	if code, _ := e.do(t, "POST", "/mcp", map[string]any{}, map[string]string{"Origin": "https://evil.example.com"}); code != 403 {
		t.Fatalf("foreign origin on mcp: %d", code)
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

func TestMCP(t *testing.T) {
	e := setup(t)
	ctx := context.Background()
	client := mcp.NewClient(&mcp.Implementation{Name: "test", Version: "1"}, nil)
	cs, err := client.Connect(ctx, &mcp.StreamableClientTransport{Endpoint: e.base + "/mcp"}, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer cs.Close()

	tools, err := cs.ListTools(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	var names []string
	for _, tl := range tools.Tools {
		names = append(names, tl.Name)
	}
	if strings.Join(names, ",") != "get_status,set_hosts_group,set_proxy" {
		t.Fatalf("tools: %v", names)
	}

	call := func(name string, args map[string]any) map[string]any {
		t.Helper()
		res, err := cs.CallTool(ctx, &mcp.CallToolParams{Name: name, Arguments: args})
		if err != nil {
			t.Fatal(err)
		}
		if res.IsError {
			return map[string]any{"error": res.Content[0].(*mcp.TextContent).Text}
		}
		b, _ := json.Marshal(res.StructuredContent)
		var m map[string]any
		json.Unmarshal(b, &m)
		return m
	}

	st := call("get_status", nil)
	groups := st["groups"].([]any)
	if len(groups) != 2 || groups[1].(map[string]any)["enabled"] != false {
		t.Fatalf("status: %v", st)
	}
	if r := call("set_hosts_group", map[string]any{"name": "Demo", "enabled": true}); r["enabled"] != true {
		t.Fatalf("set group: %v", r)
	}
	if b, _ := os.ReadFile(e.hosts); !strings.Contains(string(b), "\n127.0.0.1  demo.example.com\n") {
		t.Fatalf("hosts not updated:\n%s", b)
	}
	if r := call("set_hosts_group", map[string]any{"name": "Nope", "enabled": true}); !strings.Contains(fmt.Sprint(r["error"]), "no such group") {
		t.Fatalf("missing group: %v", r)
	}
	if r := call("set_hosts_group", map[string]any{"enabled": true}); r["error"] == nil {
		// name is required by the schema
		t.Fatalf("missing name accepted: %v", r)
	}
	os.WriteFile(e.app.ProxyConfPath(), []byte(fmt.Sprintf("* -> :%d", backend(t, "mcp"))), 0o644)
	if r := call("set_proxy", map[string]any{"enabled": true}); r["running"] != true {
		t.Fatalf("set proxy: %v", r)
	}
	if got := e.viaProxy(t, "x.test"); got != "mcp" {
		t.Fatalf("proxy via mcp: %q", got)
	}
	if r := call("set_proxy", map[string]any{"enabled": false}); r["running"] != false {
		t.Fatalf("stop proxy: %v", r)
	}
}
