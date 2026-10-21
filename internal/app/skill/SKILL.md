---
name: hoststray
description: Switch hosts-file groups on or off and start or stop the local HTTPS dev proxy through the Hosts Tray app. Use when the user wants a domain pointed at their local machine (or back), wants to test against real hostnames locally, or asks about the hosts file or the Hosts Tray proxy.
---

# Hosts Tray

Hosts Tray runs in the user's menu bar / system tray. It manages **groups** in
the hosts file (named blocks of entries pointing domains at local addresses)
and an HTTPS **proxy** that serves any hostname with a certificate from a
local CA and forwards to the routes in `proxy.conf`.

Talk to it over HTTP on `{{BASE_URL}}`. Every `/api/` call needs the token
from `{{TOKEN_PATH}}` in an `X-Hoststray-Token` header. The token changes
each time the app starts, so read the file fresh rather than reusing an old
value. On Windows PowerShell, call `curl.exe`, not `curl`.

```sh
TOKEN=$(cat "{{TOKEN_PATH}}")
curl -s {{BASE_URL}}/health                                   # no token; is it running?
curl -s -H "X-Hoststray-Token: $TOKEN" {{BASE_URL}}/api/status
```

`/api/status` returns the groups with their entries and `enabled` state, the
proxy's state, port, routes and whether its CA is trusted, and whether
switching a group needs the user's password (`hostsPasswordless`).

## Switch a group on or off

```sh
curl -s -H "X-Hoststray-Token: $TOKEN" -H "Content-Type: application/json" \
  -d '{"name":"DEV","enabled":true}' {{BASE_URL}}/api/group
```

Use a group name exactly as `/api/status` lists it. If `hostsPasswordless` is
false the user gets a password / UAC prompt, so tell them to expect it; the
request waits for their answer.

| Status | Meaning |
| --- | --- |
| 200 | Done. `elevated` says whether the user had to approve it. |
| 404 | No group by that name. |
| 409 | The user declined the password prompt. Don't retry on your own. |

## Add hostnames to a group

```sh
curl -s -H "X-Hoststray-Token: $TOKEN" -H "Content-Type: application/json" \
  -d '{"group":"DEV","entries":[{"ip":"127.0.0.1","host":"app.example.com"}]}' \
  {{BASE_URL}}/api/group/entries
```

Creates the group if there is none. A hostname already in the group gets the
new address. New entries follow the group's on/off state (on in a new group).
IPv4 addresses only, up to 50 entries at a time.

The user sees a dialog listing the entries and decides; saving then usually
asks for their password / UAC as well. Tell them what you're adding and why
before you call this; the request waits for their answer.

| Status | Meaning |
| --- | --- |
| 200 | Done. `added` lists what changed (empty if everything was already there). |
| 400 | Not a valid IPv4 address or hostname, or no group name. |
| 403 | The user said no (or Hosts Tray runs without its tray, so nobody can be asked). Don't retry on your own. |
| 409 | The user declined the password prompt. Don't retry on your own. |

## Start or stop the proxy

```sh
curl -s -H "X-Hoststray-Token: $TOKEN" -H "Content-Type: application/json" \
  -d '{"enabled":true}' {{BASE_URL}}/api/proxy/enabled
```

Returns the proxy status. If `caTrusted` is false, browsers will show
certificate warnings; the user can trust the CA from the tray menu.

## Limits

You can switch groups, add hostnames (with the user's consent) and start or
stop the proxy. Removing entries, renaming groups and changing proxy routes are
for the user, in the Hosts Tray console (**Open Hosts Tray…** in the tray menu);
ask them to do it.

If the token file is missing or `/health` doesn't answer, Hosts Tray isn't
running: ask the user to start it. A 401 means the app restarted since you
read the token; read the file again.
