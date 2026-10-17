package app

import (
	_ "embed"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

// Agents use the HTTP API with their own token, written to the data folder
// (readable only by the user) so a coding agent running as the user can pick
// it up. It only reaches the agent endpoints; skill/SKILL.md describes them.

//go:embed skill/SKILL.md
var skillTemplate string

// TokenPath is where the current launch's agent token is written.
func (a *App) TokenPath() string { return filepath.Join(a.cfg.DataDir, "token") }

// writeToken replaces the token file. Removing it first means a new file is
// created, so the 0600 mode applies even if an older file was looser (on
// Windows the file takes the data folder's ACL, which is the user's profile).
// If it can't be written, no stale token is left behind for agents to try.
func (a *App) writeToken() error {
	path := a.TokenPath()
	os.Remove(path)
	if err := os.WriteFile(path, []byte(a.agentTok), 0o600); err != nil {
		os.Remove(path)
		return err
	}
	return nil
}

// removeToken deletes the token file if it is still ours, so agents can tell
// the app isn't running.
func (a *App) removeToken() {
	if b, err := os.ReadFile(a.TokenPath()); err == nil && string(b) == a.agentTok {
		os.Remove(a.TokenPath())
	}
}

// BaseURL is the admin server's address.
func (a *App) BaseURL() string { return "http://127.0.0.1:" + strconv.Itoa(a.cfg.AdminPort) }

// Skill is the agent skill with this machine's URL and token path filled in.
func (a *App) Skill() string {
	return strings.NewReplacer("{{BASE_URL}}", a.BaseURL(), "{{TOKEN_PATH}}", filepath.ToSlash(a.TokenPath())).Replace(skillTemplate)
}

// SkillInstallPath is where Claude Code looks for the user's skills.
func SkillInstallPath() (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(home, ".claude", "skills", "hoststray", "SKILL.md"), nil
}

// StandardSetup reports whether this instance uses the default admin port and
// data folder, i.e. isn't a test run. Only then is its skill worth keeping.
func (a *App) StandardSetup() bool {
	return a.cfg.AdminPort == 47443 && os.Getenv("HOSTSTRAY_DATA_DIR") == ""
}

// RefreshSkill rewrites an installed skill that has gone stale (after an
// update, or one installed from a test run). It never installs one.
func (a *App) RefreshSkill() {
	path, err := SkillInstallPath()
	if err != nil || !a.StandardSetup() {
		return
	}
	if b, err := os.ReadFile(path); err == nil && string(b) != a.Skill() {
		os.WriteFile(path, []byte(a.Skill()), 0o644)
	}
}

// InstallSkill writes the skill where Claude Code finds it and returns the path.
func (a *App) InstallSkill() (string, error) {
	path, err := SkillInstallPath()
	if err != nil {
		return "", err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return "", err
	}
	return path, os.WriteFile(path, []byte(a.Skill()), 0o644)
}
