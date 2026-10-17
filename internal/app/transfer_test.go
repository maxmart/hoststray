package app

import (
	"encoding/json"
	"errors"
	"os"
	"strings"
	"testing"
)

const routesConf = "# my routes\n\n* -> :3000\nwss://*/ws -> :3001\n"

func TestExport(t *testing.T) {
	e := setup(t)
	os.WriteFile(e.app.ProxyConfPath(), []byte(routesConf), 0o644)
	text, err := e.app.Export()
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"[hosts]\n#==== Staging\n127.0.0.1  app.example.com\n#====\n#==== Demo\n#127.0.0.1  demo.example.com\n#====\n",
		"[routes]\n* -> :3000\nwss://*/ws -> :3001\n"} {
		if !strings.Contains(text, want) {
			t.Errorf("export lacks %q:\n%s", want, text)
		}
	}
	// Machine-specific lines and route comments stay behind.
	if strings.Contains(text, "localhost") || strings.Contains(text, "my routes") {
		t.Errorf("export has local lines:\n%s", text)
	}
}

func TestImport(t *testing.T) {
	src := setup(t)
	os.WriteFile(src.app.ProxyConfPath(), []byte(routesConf), 0o644)
	export, _ := src.app.Export()

	// Another computer: its own lines, a local group, and an older Staging.
	dst := setup(t)
	os.WriteFile(dst.hosts, []byte("127.0.0.1 localhost\n10.0.0.1 nas\n#==== Local\n127.0.0.1  mine.test\n#====\n#==== Staging\n127.0.0.1  old.example.com\n127.0.0.1  older.example.com\n#====\n"), 0o644)
	os.WriteFile(dst.app.ProxyConfPath(), []byte("# header\n\n* -> :80\n"), 0o644)

	plan, err := dst.app.PreviewImport(export)
	if err != nil {
		t.Fatal(err)
	}
	b, _ := json.Marshal(plan)
	if got := string(b); !strings.Contains(got, `{"name":"Staging","action":"replace","before":2,"after":1,"enabled":true}`) ||
		!strings.Contains(got, `{"name":"Demo","action":"add","before":0,"after":1,"enabled":false}`) ||
		strings.Contains(got, "Local") || !strings.Contains(got, `"changed":true`) {
		t.Fatalf("plan: %s", got)
	}
	if b, _ := os.ReadFile(dst.hosts); strings.Contains(string(b), "demo") {
		t.Fatal("preview changed the hosts file")
	}

	if _, _, err := dst.app.ImportExport(export); err != nil {
		t.Fatal(err)
	}
	want := "127.0.0.1 localhost\n10.0.0.1 nas\n#==== Local\n127.0.0.1  mine.test\n#====\n#==== Staging\n127.0.0.1  app.example.com\n#====\n#==== Demo\n#127.0.0.1  demo.example.com\n#====\n"
	if b, _ := os.ReadFile(dst.hosts); string(b) != want {
		t.Errorf("hosts:\n%s\nwant:\n%s", b, want)
	}
	if b, _ := os.ReadFile(dst.app.ProxyConfPath()); string(b) != "# header\n\n* -> :3000\nwss://*/ws -> :3001\n" {
		t.Errorf("proxy.conf:\n%q", b)
	}

	// Importing the same file again changes nothing.
	plan, _ = dst.app.PreviewImport(export)
	for _, g := range plan.Groups {
		if g.Action != "same" {
			t.Errorf("second import: %+v", g)
		}
	}
	if plan.Routes.Changed {
		t.Error("second import: routes changed")
	}
}

func TestImportPartial(t *testing.T) {
	e := setup(t)
	os.WriteFile(e.app.ProxyConfPath(), []byte(routesConf), 0o644)
	// Only hosts: routes stay.
	if _, _, err := e.app.ImportExport("[hosts]\n#==== New\n127.0.0.1  new.test\n#====\n127.0.0.1 loose.test\n"); err != nil {
		t.Fatal(err)
	}
	if b, _ := os.ReadFile(e.app.ProxyConfPath()); string(b) != routesConf {
		t.Errorf("routes changed: %q", b)
	}
	if b, _ := os.ReadFile(e.hosts); !strings.HasSuffix(string(b), "#==== New\n127.0.0.1  new.test\n#====\n") || strings.Contains(string(b), "loose") {
		t.Errorf("hosts:\n%s", b)
	}
	if _, err := e.app.PreviewImport("127.0.0.1 example.com\n"); !errors.Is(err, ErrNotExport) {
		t.Errorf("not an export: %v", err)
	}
}

func TestTransferAPI(t *testing.T) {
	e := setup(t)
	agent, _ := os.ReadFile(e.app.TokenPath())
	for _, ep := range []string{"GET /api/export", "POST /api/import/preview", "POST /api/import"} {
		method, path, _ := strings.Cut(ep, " ")
		if code, _ := e.do(t, method, path, map[string]any{"text": "[hosts]\n"}, map[string]string{"X-Hoststray-Token": string(agent)}); code != 401 {
			t.Errorf("agent token on %s: %d", ep, code)
		}
	}
	tok := map[string]string{"X-Hoststray-Token": e.app.Token()}
	code, b := e.do(t, "GET", "/api/export", nil, tok)
	if code != 200 || !strings.Contains(string(b), "[hosts]") {
		t.Fatalf("export: %d %s", code, b)
	}
	if code, _ := e.do(t, "POST", "/api/import/preview", map[string]any{"text": "nope"}, tok); code != 400 {
		t.Errorf("bad preview: %d", code)
	}
	code, b = e.do(t, "POST", "/api/import", map[string]any{"text": string(b)}, tok)
	if code != 200 || !strings.Contains(string(b), `"ok":true`) {
		t.Errorf("import: %d %s", code, b)
	}
}

func TestImportKeepsFinalNewlineStyle(t *testing.T) {
	e := setup(t)
	os.WriteFile(e.app.ProxyConfPath(), []byte("* -> :80\r\nwss://*/a -> :81"), 0o644) // CRLF, no final newline
	if _, _, err := e.app.ImportExport("[routes]\n* -> :3000\n"); err != nil {
		t.Fatal(err)
	}
	if b, _ := os.ReadFile(e.app.ProxyConfPath()); string(b) != "* -> :3000" {
		t.Errorf("proxy.conf: %q", b)
	}
}
