package update

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
)

func TestNewer(t *testing.T) {
	for _, c := range []struct {
		a, b string
		want bool
	}{
		{"0.11.1", "0.11.0", true}, {"v1.0.0", "0.99.9", true}, {"0.11.0", "0.11.0", false},
		{"0.10.9", "0.11.0", false}, {"0.12", "0.11.5", true}, {"1", "0.9.9", true},
		{"0.11.0", "dev", false}, {"garbage", "0.1.0", false}, {"0.11.0-beta", "0.10.0", false},
	} {
		if got := Newer(c.a, c.b); got != c.want {
			t.Errorf("Newer(%q, %q) = %v", c.a, c.b, got)
		}
	}
}

type feed struct {
	tag     string
	payload []byte
	sums    string // "" = correct sums, "-" = no SHA256SUMS asset
	status  int
}

func serve(t *testing.T, f feed) *httptest.Server {
	var srv *httptest.Server
	srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		name := AssetName(strings.TrimPrefix(f.tag, "v"))
		switch r.URL.Path {
		case "/latest":
			if f.status != 0 {
				w.WriteHeader(f.status)
				return
			}
			assets := []Asset{{Name: name, URL: srv.URL + "/dl/" + name}, {Name: "other.zip", URL: srv.URL + "/dl/other"}}
			if f.sums != "-" {
				assets = append(assets, Asset{Name: "SHA256SUMS", URL: srv.URL + "/dl/SHA256SUMS"})
			}
			json.NewEncoder(w).Encode(Release{Tag: f.tag, Assets: assets})
		case "/dl/SHA256SUMS":
			if f.sums != "" {
				fmt.Fprint(w, f.sums)
				return
			}
			h := sha256.Sum256(f.payload)
			fmt.Fprintf(w, "%s  other.zip\n%s  %s\n", strings.Repeat("0", 64), hex.EncodeToString(h[:]), name)
		case "/dl/" + name:
			w.Write(f.payload)
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(srv.Close)
	return srv
}

func TestCheckAndDownload(t *testing.T) {
	ctx := context.Background()
	srv := serve(t, feed{tag: "v0.12.0", payload: []byte("new build")})

	if av, err := Check(ctx, srv.URL+"/latest", "0.12.0"); err != nil || av != nil {
		t.Fatalf("same version: %v %v", av, err)
	}
	av, err := Check(ctx, srv.URL+"/latest", "0.11.0")
	if err != nil || av == nil || av.Version != "0.12.0" || av.Asset.Name != AssetName("0.12.0") {
		t.Fatalf("check: %+v %v", av, err)
	}
	dir := t.TempDir()
	path, err := Download(ctx, av, dir)
	if err != nil {
		t.Fatal(err)
	}
	if b, _ := os.ReadFile(path); string(b) != "new build" {
		t.Fatalf("content %q", b)
	}
}

func TestRefusals(t *testing.T) {
	ctx := context.Background()
	// Wrong checksum: refused, and nothing left behind.
	srv := serve(t, feed{tag: "v0.12.0", payload: []byte("tampered"), sums: strings.Repeat("a", 64) + "  " + AssetName("0.12.0") + "\n"})
	av, err := Check(ctx, srv.URL+"/latest", "0.11.0")
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	if _, err := Download(ctx, av, dir); err == nil || !strings.Contains(err.Error(), "checksum mismatch") {
		t.Fatalf("tampered download: %v", err)
	}
	if entries, _ := os.ReadDir(dir); len(entries) != 0 {
		t.Fatalf("left files: %v", entries)
	}
	// Asset missing from SHA256SUMS.
	srv = serve(t, feed{tag: "v0.12.0", payload: []byte("x"), sums: strings.Repeat("a", 64) + "  something-else\n"})
	av, _ = Check(ctx, srv.URL+"/latest", "0.11.0")
	if _, err := Download(ctx, av, t.TempDir()); err == nil || !strings.Contains(err.Error(), "not listed") {
		t.Fatalf("unlisted: %v", err)
	}
	// No SHA256SUMS at all.
	srv = serve(t, feed{tag: "v0.12.0", payload: []byte("x"), sums: "-"})
	if _, err := Check(ctx, srv.URL+"/latest", "0.11.0"); err == nil {
		t.Fatal("release without SHA256SUMS accepted")
	}
	// No releases yet.
	srv = serve(t, feed{status: 404})
	if av, err := Check(ctx, srv.URL+"/latest", "0.11.0"); av != nil || err != nil {
		t.Fatalf("404: %v %v", av, err)
	}
	// Server error.
	srv = serve(t, feed{status: 500})
	if _, err := Check(ctx, srv.URL+"/latest", "0.11.0"); err == nil {
		t.Fatal("500 not reported")
	}
}
