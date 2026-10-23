# Contributing

## Development

Needs Go 1.27 or newer; on macOS, Xcode command line tools (the tray uses cgo).

```sh
go run .                         # run from source
go test ./...                    # unit and integration tests
```

On Windows, run `go generate . ./internal/platform` before building: the first
links in the icon and manifest (without it, dialogs fall back to plain Yes/No
boxes), the second builds the helper service the app carries inside it.

To try things without touching the real hosts file, copy it somewhere and run
with `HOSTS_PATH` pointing at the copy.

The hosts and `proxy.conf` parsers were ported from the original JavaScript
version; `internal/*/testdata/js_golden.json` holds that version's output for 800 inputs
each, and the tests check the Go port produces exactly the same.

Two opt-in macOS test suites need someone at the screen:

- `HOSTSTRAY_UI_TESTS=1 go test ./internal/platform/` clicks real dialogs.
- `HOSTSTRAY_ADMIN_TESTS=1 go test -run Admin ./internal/platform/` runs the
  password prompts (elevated write, password-free on/off, CA trust) against a
  throwaway file and CA. You type your password five times.

## Releasing

```sh
VERSION=0.11.0 ./scripts/build-release.sh   # build everything into dist/
VERSION=0.11.0 ./scripts/release.sh         # publish dist/ as a GitHub release (gh CLI)
```

`build-release.sh` produces `Hosts-Tray-<v>-mac.zip` and `.pkg` (universal,
signed and notarized, via `scripts/build-mac.sh`),
`hoststray-<v>-windows-{amd64,arm64}.exe` with icon, manifest and the helper service, their
installers `Hosts-Tray-<v>-windows-{amd64,arm64}-setup.exe` (needs
`brew install makensis`; skipped without it, see `scripts/windows/installer.nsi`),
and the `SHA256SUMS` the updater requires.

macOS signing needs, in your keychain, a **Developer ID Application**
certificate (and **Developer ID Installer** for the `.pkg`), plus an
app-specific password for notarization. Copy `.env.example` to `.env` and fill
it in. Without it, `build-mac.sh` builds an ad-hoc signed app for local use;
`NOTARIZE=0` signs without notarizing, for quick test builds.

The Windows executables and installers are not code-signed yet, so
SmartScreen warns on first run.
