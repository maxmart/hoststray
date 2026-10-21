// Package helper is the privileged hosts helper: a small root daemon (macOS)
// that switches hosts file groups for the user who installed it, so toggles
// don't need a password, and resets browser connections to where a hostname
// used to point. It only flips groups that are already in the hosts file;
// editing the file itself still goes through the password prompt.
//
// The daemon is its own binary (cmd/hoststray-helper), shipped inside the app
// and copied to a root-owned folder on install. The app talks to it over a
// Unix socket only that user can open, one JSON request and one response per
// connection.
package helper

import "errors"

const (
	Label = "maxmart.hoststray.helper"
	// Proto is bumped when requests change.
	Proto = 2
)

// ErrNotRunning means there is no helper to ask; write with a password
// prompt instead.
var ErrNotRunning = errors.New("hosts helper not running")

// ErrNoGroup is returned when the hosts file has no group by that name.
var ErrNoGroup = errors.New("no such group")

type Request struct {
	Op     string `json:"op"` // "version" or "group"
	Group  string `json:"group,omitempty"`
	Enable bool   `json:"enable,omitempty"`
}

type Response struct {
	Proto   int    `json:"proto,omitempty"`
	NoGroup bool   `json:"noGroup,omitempty"`
	Error   string `json:"error,omitempty"`
}
