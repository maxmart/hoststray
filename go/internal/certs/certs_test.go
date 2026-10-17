package certs

import (
	"crypto/tls"
	"crypto/x509"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"testing"
	"time"

	"github.com/maxmart/hoststray/internal/difftest"
)

func pool(a *Authority) *x509.CertPool {
	p := x509.NewCertPool()
	p.AddCert(a.Cert())
	return p
}

func checkLeaf(t *testing.T, a *Authority, c *tls.Certificate, name string) {
	t.Helper()
	leaf := c.Leaf
	if _, err := leaf.Verify(x509.VerifyOptions{Roots: pool(a), DNSName: name, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}); err != nil {
		t.Fatalf("verify %s: %v", name, err)
	}
	if d := leaf.NotAfter.Sub(leaf.NotBefore); d > 825*24*time.Hour {
		t.Fatalf("validity %v too long for macOS", d)
	}
	if len(c.Certificate) != 2 {
		t.Fatalf("chain should include the CA, got %d certs", len(c.Certificate))
	}
}

func TestNewCA(t *testing.T) {
	dir := t.TempDir()
	a, created, err := Open(dir)
	if err != nil || !created {
		t.Fatalf("open: %v created=%v", err, created)
	}
	if !a.Cert().IsCA {
		t.Fatal("not a CA")
	}
	if fi, _ := os.Stat(filepath.Join(dir, caName+".key")); runtime.GOOS != "windows" && fi.Mode().Perm() != 0o600 {
		t.Fatalf("key perms %v", fi.Mode().Perm())
	}
	c1, err := a.Leaf("app.example.com")
	if err != nil {
		t.Fatal(err)
	}
	checkLeaf(t, a, c1, "app.example.com")

	// Reopen: same CA, and the leaf comes back from disk unchanged.
	b, created, err := Open(dir)
	if err != nil || created {
		t.Fatalf("reopen: %v created=%v", err, created)
	}
	c2, _ := b.Leaf("app.example.com")
	if string(c2.Leaf.Raw) != string(c1.Leaf.Raw) {
		t.Fatal("leaf not reused from disk")
	}
	// A different CA must not accept the old leaves.
	other, _, _ := Open(t.TempDir())
	os.WriteFile(filepath.Join(other.dir, "app.example.com.crt"), mustRead(t, filepath.Join(dir, "app.example.com.crt")), 0o644)
	os.WriteFile(filepath.Join(other.dir, "app.example.com.key"), mustRead(t, filepath.Join(dir, "app.example.com.key")), 0o600)
	c3, _ := other.Leaf("app.example.com")
	checkLeaf(t, other, c3, "app.example.com")
}

func mustRead(t *testing.T, p string) []byte {
	b, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestInvalidNames(t *testing.T) {
	a, _, _ := Open(t.TempDir())
	for _, n := range []string{"../evil", "a/b", "a\\b", "..", "-x", "x y", "", "a..b"} {
		if _, err := a.Leaf(n); err == nil {
			t.Errorf("accepted %q", n)
		}
	}
	c, err := a.GetCertificate(&tls.ClientHelloInfo{ServerName: "API.Example.COM."})
	if err != nil {
		t.Fatal(err)
	}
	checkLeaf(t, a, c, "api.example.com")
	if c, err := a.GetCertificate(&tls.ClientHelloInfo{}); err != nil || c.Leaf.DNSNames[0] != "localhost" {
		t.Fatalf("no-SNI fallback: %v", err)
	}
}

// TestLegacyCA loads the CA created by the Electron version (node-forge, RSA
// PKCS#1) and checks that its non-compliant leaf certs get replaced.
func TestLegacyCA(t *testing.T) {
	src := filepath.Join(difftest.RepoRoot(), "_certs")
	if _, err := os.Stat(filepath.Join(src, caName+".crt")); err != nil {
		t.Skip("no legacy _certs in repo")
	}
	dir := t.TempDir()
	entries, _ := os.ReadDir(src)
	for _, e := range entries {
		os.WriteFile(filepath.Join(dir, e.Name()), mustRead(t, filepath.Join(src, e.Name())), 0o600)
	}
	a, created, err := Open(dir)
	if err != nil || created {
		t.Fatalf("open legacy: %v created=%v", err, created)
	}
	old := mustRead(t, filepath.Join(dir, "local.cupmanager.net.crt"))
	c, err := a.Leaf("local.cupmanager.net")
	if err != nil {
		t.Fatal(err)
	}
	checkLeaf(t, a, c, "local.cupmanager.net")
	if string(mustRead(t, filepath.Join(dir, "local.cupmanager.net.crt"))) == string(old) {
		t.Fatal("legacy leaf (no serverAuth, 1001 days) was not replaced")
	}
	checkApple(t, dir, a, "local.cupmanager.net")
}

func TestApplePolicy(t *testing.T) {
	dir := t.TempDir()
	a, _, _ := Open(dir)
	if _, err := a.Leaf("app.example.com"); err != nil {
		t.Fatal(err)
	}
	checkApple(t, dir, a, "app.example.com")
}

// checkApple runs macOS's own SSL policy check on the issued leaf.
func checkApple(t *testing.T, dir string, a *Authority, name string) {
	t.Helper()
	if runtime.GOOS != "darwin" {
		return
	}
	out, err := exec.Command("security", "verify-cert", "-c", filepath.Join(dir, name+".crt"),
		"-r", a.CertPath(), "-p", "ssl", "-s", name, "-L", "-q").CombinedOutput()
	if err != nil {
		t.Fatalf("macOS rejects the leaf: %v\n%s", err, out)
	}
}

func TestTrustedIsFalseForNewCA(t *testing.T) {
	a, _, _ := Open(t.TempDir())
	if a.Trusted() {
		t.Fatal("a brand-new CA can't be trusted by the OS")
	}
}
