// Hosts Tray: toggles hosts file groups and runs a local HTTPS dev proxy, from
// a tray icon. Agents drive it over the local HTTP API (internal/app/skill).
package main

// Windows needs an icon and a manifest (DPI awareness, common controls v6)
// linked in as a resource; without the manifest, dialogs fall back to the
// old MessageBox look. Release builds do this in scripts/build-release.sh;
// for a local build run `go generate ./...` once first.
//go:generate go run github.com/tc-hib/go-winres@v0.3.3 simply --icon scripts/icon.png --manifest gui --product-name "Hosts Tray" --file-description "Hosts Tray" --original-filename hoststray.exe --arch amd64,arm64

import (
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"syscall"
	"time"

	"github.com/maxmart/hoststray/internal/app"
	"github.com/maxmart/hoststray/internal/platform"
)

var version = "dev" // set with -ldflags "-X main.version=..."

func main() {
	headless := flag.Bool("headless", false, "run without a tray icon (editors and API still served)")
	showVersion := flag.Bool("version", false, "print the version and exit")
	flag.Parse()
	if *showVersion {
		fmt.Println(version)
		return
	}

	cfg := app.ConfigFromEnv(version)
	cfg.Interactive = !*headless
	setupLog(cfg.DataDir)

	a, err := app.New(cfg)
	if err != nil {
		fatal(cfg, "Hosts Tray could not start.\n\n"+err.Error())
	}
	ln, err := a.Listen()
	// After an update the previous version may still be shutting down.
	for i := 0; err != nil && os.Getenv("HOSTSTRAY_RESTART") != "" && i < 50; i++ {
		time.Sleep(200 * time.Millisecond)
		ln, err = a.Listen()
	}
	os.Unsetenv("HOSTSTRAY_RESTART")
	if err != nil {
		if alreadyRunning(cfg.AdminPort) {
			fatal(cfg, "Hosts Tray is already running. Look for its icon in the menu bar or system tray.")
		}
		fatal(cfg, fmt.Sprintf("Hosts Tray could not open its local port %d.\n\n%v", cfg.AdminPort, err))
	}
	go a.Serve(ln)
	log.Printf("Hosts Tray %s: hosts %s, data %s, API %s", version, cfg.HostsPath, cfg.DataDir, a.BaseURL())

	a.RefreshSkill()
	a.RestoreProxy()
	a.StartUpdateChecks()
	// Working on a hosts copy is a test setup: show the editor straight away.
	if os.Getenv("HOSTS_PATH") != "" && !*headless {
		platform.OpenURL(a.EditorURL("hosts"))
	}
	if os.Getenv("OPEN_PROXY_EDITOR") != "" && !*headless {
		platform.OpenURL(a.EditorURL("routes"))
	}

	if *headless {
		a.SetQuit(func() { a.Shutdown(); os.Exit(0) })
		sig := make(chan os.Signal, 1)
		signal.Notify(sig, os.Interrupt, syscall.SIGTERM)
		<-sig
		a.Shutdown()
		return
	}
	runTray(a)
}

// setupLog writes to stderr and to hoststray.log in the data folder, which is
// the only place to look when running from the tray.
func setupLog(dir string) {
	os.MkdirAll(dir, 0o755)
	path := filepath.Join(dir, "hoststray.log")
	if fi, err := os.Stat(path); err == nil && fi.Size() > 2<<20 {
		os.Rename(path, path+".1")
	}
	f, err := os.OpenFile(path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o644)
	if err != nil {
		return
	}
	log.SetOutput(io.MultiWriter(bestEffort{os.Stderr}, f))
}

// bestEffort swallows its writer's errors. A GUI build has no console, so on
// Windows every write to stderr fails, and io.MultiWriter stops at the first
// error — which would leave the log file empty exactly when it is the only
// place to look.
type bestEffort struct{ w io.Writer }

func (b bestEffort) Write(p []byte) (int, error) {
	b.w.Write(p)
	return len(p), nil
}

func alreadyRunning(port int) bool {
	c := &http.Client{Timeout: 2 * time.Second}
	resp, err := c.Get("http://127.0.0.1:" + strconv.Itoa(port) + "/health")
	if err != nil {
		return false
	}
	resp.Body.Close()
	return resp.StatusCode == 200
}

func fatal(cfg app.Config, msg string) {
	log.Print(msg)
	if cfg.Interactive {
		platform.Alert("Hosts Tray", msg)
	}
	os.Exit(1)
}
