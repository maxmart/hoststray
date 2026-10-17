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

func (a *App) writeToken() error {
	return os.WriteFile(a.TokenPath(), []byte(a.agentTok), 0o600)
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
