# Handoff: bring the Windows helper in line with macOS

For the Claude Code session on the Windows machine. The macOS helper was
redesigned after a security review; Windows still runs the first version
(`internal/platform/helper_windows.go`) and keeps working unchanged, because
the shared code falls back to it. Port these points, test on Windows, then
delete this file.

## What changed on macOS, and what to do on Windows

1. **Groups only.** The helper no longer takes whole hosts files. The only
   requests are `version` and `group` (`{"op":"group","group":"dev","enable":true}`,
   `helper.Proto` = 2; types in `internal/helper/helper.go`). The helper reads
   the hosts file itself, flips the group with `hosts.SetGroup`, and writes it.
   Any process running as the user can still ask, but it can only switch
   entries the user wrote; edits and imports go through the UAC prompt.
   - App side: `app.SetGroup` calls `platform.HelperSetGroup` first, and falls
     back to the full write when it returns `handled == false`. The Windows
     `helperSetGroup` is a stub returning false; implement it with the new
     request, and make `helperWrite` return `errNoHelper` (as on macOS) so
     editor saves prompt.
2. **The helper computes the drop list itself** with `hosts.MovedAway(old,
   next)` (now in `internal/hosts/moved.go`), before writing. Callers can no
   longer name addresses to reset. `MovedAway` takes the old address straight
   from the old hosts file when there is one (Go caches the hosts file for 5 s,
   so a lookup right after a change is stale) and only uses DNS for names the
   file didn't cover.
3. **Its own small binary.** `cmd/hoststray-helper` is the daemon on macOS (no
   cgo, no tray/proxy/updater code); `main_other.go` is an empty stub for
   Windows. Move the service code there, ship `hoststray-helper.exe` next to
   `hoststray.exe` (installer + `scripts/build-release.sh`), and have install
   copy that instead of the app exe.
4. **Limits.** At most 4 requests at once (`maxConns`), requests up to 64 KB.
5. **Atomic write**: temp file in the same folder, then rename (see
   `writeAtomic` in `internal/helper/daemon_darwin.go`). On Windows use
   `MoveFileEx(MOVEFILE_REPLACE_EXISTING)`; check Defender doesn't hold it.
6. **Logging**: the macOS daemon logs each request to
   `/var/log/hoststray-helper.log`. The Windows service could use the event log
   or a file under `%ProgramData%`.
7. **Self-removal**: install records the app's exe path; the daemon checks it
   every 10 minutes and uninstalls itself when it has been missing for a
   minute (an update renames it briefly).
8. **Updates**: `platform.HelperOutdated()` compares the installed helper with
   the bundled one (`helper.Differs`); on start the app offers to reinstall
   (`App.OfferHelperUpdate`). The Windows stub returns false.

## Also check on Windows: something else on port 443

On macOS the most specific bind wins: with another program on
`127.0.0.1:443`, `net.Listen(":443")` succeeded and every hostname pointed at
loopback went to that program, silently. (Binding 127.0.0.1:443 ourselves
isn't an option there: below port 1024 a normal app may only bind the
wildcard address.) The proxy now checks, on start and every 30 s, that a
connection to 127.0.0.1 and ::1 on its port reaches itself
(`checkLoopback` in `internal/proxy/proxy.go`), and fails or alerts
otherwise. This runs on Windows too; check what Windows does when another
program holds `127.0.0.1:443` or `0.0.0.0:443` before and after the proxy
starts (IIS, Skype and VPN clients are the usual suspects), and that the
check doesn't misfire there.
