// Package update checks GitHub Releases for a newer version, downloads and
// verifies it, and swaps it in.
//
// A release must carry a SHA256SUMS asset listing every download. On macOS the
// new app must also be validly signed by the same team as the running one.
package update

import (
	"bufio"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"time"
)

// DefaultURL is the GitHub API endpoint for the latest release.
const DefaultURL = "https://api.github.com/repos/maxmart/hoststray/releases/latest"

type Release struct {
	Tag    string  `json:"tag_name"`
	Assets []Asset `json:"assets"`
}

type Asset struct {
	Name string `json:"name"`
	URL  string `json:"browser_download_url"`
}

// Available describes a newer release and the asset for this platform.
type Available struct {
	Version string
	Asset   Asset
	SumsURL string
}

// AssetName is the release file for this OS/architecture.
func AssetName(version string) string {
	switch runtime.GOOS {
	case "darwin":
		return "Hosts-Tray-" + version + "-mac.zip"
	case "windows":
		return "hoststray-" + version + "-windows-" + runtime.GOARCH + ".exe"
	default:
		return "hoststray-" + version + "-linux-" + runtime.GOARCH
	}
}

// Newer reports whether version a is newer than b (dotted numbers, an
// optional leading "v"; anything unparseable is never newer).
func Newer(a, b string) bool {
	pa, oka := parse(a)
	pb, okb := parse(b)
	if !oka || !okb {
		return false
	}
	for i := 0; i < 3; i++ {
		if pa[i] != pb[i] {
			return pa[i] > pb[i]
		}
	}
	return false
}

func parse(v string) ([3]int, bool) {
	var out [3]int
	parts := strings.Split(strings.TrimPrefix(strings.TrimSpace(v), "v"), ".")
	if len(parts) == 0 || len(parts) > 3 {
		return out, false
	}
	for i, p := range parts {
		n, err := strconv.Atoi(p)
		if err != nil || n < 0 {
			return out, false
		}
		out[i] = n
	}
	return out, true
}

var client = &http.Client{Timeout: 5 * time.Minute}

// Check returns the newer release for this platform, or nil if up to date.
func Check(ctx context.Context, url, current string) (*Available, error) {
	req, _ := http.NewRequestWithContext(ctx, "GET", url, nil)
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("User-Agent", "hoststray/"+current)
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusNotFound {
		return nil, nil // no releases yet
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("release check: %s", resp.Status)
	}
	var rel Release
	if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&rel); err != nil {
		return nil, err
	}
	version := strings.TrimPrefix(rel.Tag, "v")
	if !Newer(version, current) {
		return nil, nil
	}
	av := &Available{Version: version}
	want := AssetName(version)
	for _, a := range rel.Assets {
		switch a.Name {
		case want:
			av.Asset = a
		case "SHA256SUMS":
			av.SumsURL = a.URL
		}
	}
	if av.Asset.URL == "" {
		return nil, nil // no build for this platform in that release
	}
	if av.SumsURL == "" {
		return nil, errors.New("release " + rel.Tag + " has no SHA256SUMS; not updating")
	}
	return av, nil
}

// Download fetches the asset into dir and checks it against SHA256SUMS.
func Download(ctx context.Context, av *Available, dir string) (string, error) {
	sums, err := fetchSums(ctx, av.SumsURL)
	if err != nil {
		return "", err
	}
	want, ok := sums[av.Asset.Name]
	if !ok {
		return "", fmt.Errorf("%s is not listed in SHA256SUMS", av.Asset.Name)
	}
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return "", err
	}
	dst := filepath.Join(dir, av.Asset.Name)
	req, _ := http.NewRequestWithContext(ctx, "GET", av.Asset.URL, nil)
	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("download: %s", resp.Status)
	}
	f, err := os.Create(dst + ".part")
	if err != nil {
		return "", err
	}
	h := sha256.New()
	_, err = io.Copy(io.MultiWriter(f, h), io.LimitReader(resp.Body, 500<<20))
	f.Close()
	if err != nil {
		os.Remove(dst + ".part")
		return "", err
	}
	if got := hex.EncodeToString(h.Sum(nil)); got != want {
		os.Remove(dst + ".part")
		return "", fmt.Errorf("checksum mismatch for %s", av.Asset.Name)
	}
	return dst, os.Rename(dst+".part", dst)
}

func fetchSums(ctx context.Context, url string) (map[string]string, error) {
	req, _ := http.NewRequestWithContext(ctx, "GET", url, nil)
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("SHA256SUMS: %s", resp.Status)
	}
	sums := map[string]string{}
	sc := bufio.NewScanner(io.LimitReader(resp.Body, 1<<20))
	for sc.Scan() {
		// "<hex>  <name>" (sha256sum / shasum -a 256 format)
		f := strings.Fields(sc.Text())
		if len(f) == 2 && len(f[0]) == 64 {
			sums[strings.TrimPrefix(f[1], "*")] = strings.ToLower(f[0])
		}
	}
	return sums, sc.Err()
}

// Install replaces the running app with the downloaded file and starts the
// new version. The caller should exit right after it returns nil.
func Install(downloaded string) error { return install(downloaded) }

// Cleanup removes leftovers from a previous update (call at startup).
func Cleanup() { cleanup() }
