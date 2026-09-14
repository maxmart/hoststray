// Shared parser/serializer for the hosts file.
//
// Design goal: faithful round-trip. Parsing then serializing an *unedited*
// document must reproduce the original file byte-for-byte (modulo a single
// normalized line ending). Anything we don't explicitly model -- the Microsoft
// header, blank lines, stray comments, inline "# notes", odd whitespace, IPs
// other than 127.0.0.1 -- is carried through verbatim via each node's `raw`.
//
// A node is only re-generated from its structured fields when `raw` is null,
// which the editor sets when it actually changes that node.

const GROUP_PREFIX = "#====";

// Matches a dotted-quad. We deliberately do not try to validate IPv6 etc. --
// anything that isn't a plain IPv4 leading token is treated as a raw comment
// line and preserved untouched.
const IPV4 = /^\d{1,3}(?:\.\d{1,3}){3}$/;

function isMarker(line) {
    return line.startsWith(GROUP_PREFIX);
}

function markerName(line) {
    return line.slice(GROUP_PREFIX.length).trim();
}

// Try to interpret a single line as a host entry (optionally commented out).
// Returns { enabled, ip, host, comment } or null if it isn't an entry.
function parseEntry(line) {
    let enabled = true;
    let body = line.replace(/^\s+/, "");

    if (body.startsWith("#")) {
        enabled = false;
        body = body.slice(1);
    }

    const m = body.trim().match(/^(\S+)\s+(\S+)\s*(.*)$/);
    if (!m) return null;

    const ip = m[1];
    if (!IPV4.test(ip)) return null;

    return {
        enabled,
        ip,
        host: m[2],
        comment: m[3] ? m[3].trim() : "",
    };
}

function parse(text) {
    const eol = text.indexOf("\r\n") >= 0 ? "\r\n" : "\n";
    const lines = text.split(/\r?\n/);

    const doc = { eol, nodes: [] };
    let group = null;

    for (const raw of lines) {
        if (isMarker(raw)) {
            const name = markerName(raw);
            if (name.length > 0) {
                // Opening marker. If a group was already open without a closing
                // marker, flush it (rawClose stays null so we don't invent one).
                if (group) doc.nodes.push(group);
                group = { t: "group", name, rawOpen: raw, rawClose: null, children: [] };
            } else {
                // Closing marker.
                if (group) {
                    group.rawClose = raw;
                    doc.nodes.push(group);
                    group = null;
                } else {
                    doc.nodes.push({ t: "raw", raw });
                }
            }
            continue;
        }

        const entry = parseEntry(raw);
        const node = entry
            ? { t: "entry", raw, enabled: entry.enabled, ip: entry.ip, host: entry.host, comment: entry.comment }
            : { t: "raw", raw };

        if (group) group.children.push(node);
        else doc.nodes.push(node);
    }

    if (group) doc.nodes.push(group); // unclosed group at EOF
    return doc;
}

// Build the text for a single entry/raw node.
function lineFor(node) {
    if (node.t === "raw") return node.raw;
    if (node.raw != null) return node.raw; // untouched -> verbatim

    const host = (node.host || "").trim();
    if (!host) return null; // empty host -> drop on serialize

    let line = (node.enabled ? "" : "#") + (node.ip || "127.0.0.1") + "  " + host;
    if (node.comment) line += "  " + node.comment;
    return line;
}

function serialize(doc) {
    const out = [];
    for (const node of doc.nodes) {
        if (node.t === "group") {
            out.push(node.rawOpen != null ? node.rawOpen : GROUP_PREFIX + " " + node.name);
            for (const child of node.children) {
                const line = lineFor(child);
                if (line != null) out.push(line);
            }
            out.push(node.rawClose != null ? node.rawClose : GROUP_PREFIX);
        } else {
            const line = lineFor(node);
            if (line != null) out.push(line);
        }
    }
    return out.join(doc.eol || "\n");
}

// Convenience for the tray: derive the list of groups and whether each is fully
// enabled (no commented-out entries), matching the original tray semantics.
function getGroups(doc) {
    return doc.nodes
        .filter((n) => n.t === "group")
        .map((g) => {
            const entries = g.children.filter((c) => c.t === "entry");
            return {
                name: g.name,
                enabled: entries.length > 0 && entries.every((e) => e.enabled),
            };
        });
}

module.exports = { GROUP_PREFIX, parse, serialize, getGroups, parseEntry };
