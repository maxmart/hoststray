package app

import (
	"context"
	"log"
	"os"
	"path/filepath"
	"time"

	"github.com/maxmart/hoststray/internal/platform"
	"github.com/maxmart/hoststray/internal/update"
)

// UpdateReady is a downloaded, verified update waiting for a restart.
type UpdateReady struct {
	Version string `json:"version"`
	path    string
}

func (a *App) updatesDir() string { return filepath.Join(a.cfg.DataDir, "updates") }

// updatesEnabled is false for development builds, unless pointed at a test
// release feed.
func (a *App) updatesEnabled() bool {
	return a.cfg.Version != "dev" || os.Getenv("HOSTSTRAY_UPDATE_URL") != ""
}

func (a *App) updateURL() string {
	if u := os.Getenv("HOSTSTRAY_UPDATE_URL"); u != "" {
		return u
	}
	return update.DefaultURL
}

func (a *App) PendingUpdate() *UpdateReady {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.pending
}

// StartUpdateChecks checks shortly after launch and then every six hours.
func (a *App) StartUpdateChecks() {
	update.Cleanup()
	os.RemoveAll(a.updatesDir())
	if !a.updatesEnabled() {
		return
	}
	go func() {
		time.Sleep(5 * time.Second)
		for {
			a.CheckForUpdates(false)
			time.Sleep(6 * time.Hour)
		}
	}()
}

// CheckForUpdates downloads a newer release if there is one and offers to
// restart into it. manual reports "up to date" and errors to the user.
func (a *App) CheckForUpdates(manual bool) {
	if !a.updatesEnabled() {
		if manual && a.cfg.Interactive {
			platform.Alert("Hosts Tray", "Updates are off in development builds.")
		}
		return
	}
	if p := a.PendingUpdate(); p != nil {
		a.offerRestart(p)
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()
	av, err := update.Check(ctx, a.updateURL(), a.cfg.Version)
	if err == nil && av != nil {
		var path string
		if path, err = update.Download(ctx, av, a.updatesDir()); err == nil {
			p := &UpdateReady{Version: av.Version, path: path}
			a.mu.Lock()
			a.pending = p
			a.mu.Unlock()
			log.Printf("update %s downloaded", av.Version)
			a.changed()
			a.offerRestart(p)
			return
		}
	}
	if err != nil {
		log.Printf("update check: %v", err)
		if manual && a.cfg.Interactive {
			platform.Alert("Hosts Tray", "Could not check for updates.\n\n"+err.Error())
		}
		return
	}
	if manual && a.cfg.Interactive {
		platform.Alert("Hosts Tray", "You're on the latest version ("+a.cfg.Version+").")
	}
}

func (a *App) offerRestart(p *UpdateReady) {
	if !a.cfg.Interactive {
		return
	}
	if platform.Ask("Update ready", "Hosts Tray "+p.Version+" has been downloaded. Restart now to use it?", "Restart now", "Later") == 0 {
		a.InstallUpdate()
	}
}

// InstallUpdate swaps in the pending update and quits; the new version starts
// in our place.
func (a *App) InstallUpdate() error {
	p := a.PendingUpdate()
	if p == nil {
		return nil
	}
	a.proxy.Stop() // free the port for the new version
	if err := update.Install(p.path); err != nil {
		log.Printf("install update: %v", err)
		if a.cfg.Interactive {
			platform.Alert("Hosts Tray", "The update could not be installed.\n\n"+err.Error())
		}
		a.RestoreProxy()
		return err
	}
	log.Printf("installed update %s; restarting", p.Version)
	if a.quit != nil {
		a.quit()
	}
	return nil
}

// SetQuit sets how the app exits (the tray's quit, or os.Exit when headless).
func (a *App) SetQuit(f func()) { a.quit = f }
