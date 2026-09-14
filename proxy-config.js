// Parser/serializer for proxy.conf.
//
// Format is one rule per line:   <pattern> -> <target>
//   * -> :80                     all HTTPS web traffic -> 127.0.0.1:80
//   wss://*/cmweb -> :5124       websocket upgrades under /cmweb -> :5124
//   https://*/api -> 1.2.3.4:81  (host may be specified on the target)
//
// Blank lines and #-comments are preserved verbatim. Like hosts-model.js this
// round-trips faithfully: a line keeps its original text unless it's edited.

const fs = require("fs");
const path = require("path");

const DEFAULT_HOST = "127.0.0.1";

const DEFAULT_PROXY_CONF =
    "# Proxy routes — one \"<pattern> -> <target>\" per line.\n" +
    "#   <pattern>:  *  = all traffic   |   wss://*/path = websocket upgrades under /path\n" +
    "#   <target>:   :PORT = 127.0.0.1:PORT   |   host:PORT = a specific host\n" +
    "# Edit these from the tray menu: \"Edit proxy routes…\"\n" +
    "\n" +
    "* -> :80\n";

function parseTarget(s) {
    s = s.trim();
    let host = DEFAULT_HOST;
    let portStr = s;
    if (s.startsWith(":")) {
        portStr = s.slice(1);
    } else if (s.includes(":")) {
        const idx = s.lastIndexOf(":");
        host = s.slice(0, idx) || DEFAULT_HOST;
        portStr = s.slice(idx + 1);
    }
    const port = parseInt(portStr, 10);
    return { host, port };
}

function parsePattern(s) {
    s = s.trim();
    let proto = "";
    let rest = s;
    const m = s.match(/^([a-zA-Z]+):\/\/(.*)$/);
    if (m) {
        proto = m[1].toLowerCase();
        rest = m[2];
    }
    const ws = proto === "ws" || proto === "wss";

    let hostPattern = rest;
    let pathPrefix = "";
    const slash = rest.indexOf("/");
    if (slash >= 0) {
        hostPattern = rest.slice(0, slash);
        pathPrefix = rest.slice(slash);
    }
    if (hostPattern === "") hostPattern = "*";

    return { proto, ws, hostPattern, pathPrefix };
}

function parse(text) {
    const eol = text.indexOf("\r\n") >= 0 ? "\r\n" : "\n";
    const lines = text.split(/\r?\n/);

    const nodes = [];
    for (const raw of lines) {
        const trimmed = raw.trim();
        const arrow = raw.indexOf("->");
        if (trimmed === "" || trimmed.startsWith("#") || arrow < 0) {
            nodes.push({ t: "raw", raw });
            continue;
        }

        const pat = parsePattern(raw.slice(0, arrow));
        const tgt = parseTarget(raw.slice(arrow + 2));

        if (!Number.isFinite(tgt.port)) {
            nodes.push({ t: "raw", raw }); // unparseable target -> preserve
            continue;
        }

        nodes.push({
            t: "route",
            raw,
            ws: pat.ws,
            proto: pat.proto,
            hostPattern: pat.hostPattern,
            pathPrefix: pat.pathPrefix,
            targetHost: tgt.host,
            targetPort: tgt.port,
        });
    }

    return { eol, nodes };
}

function lineFor(node) {
    if (node.t === "raw") return node.raw;
    if (node.raw != null) return node.raw; // untouched -> verbatim

    const proto = node.ws ? node.proto || "wss" : node.proto || "";
    const pattern = (proto ? proto + "://" : "") + (node.hostPattern || "*") + (node.pathPrefix || "");

    const host = node.targetHost && node.targetHost !== DEFAULT_HOST ? node.targetHost : "";
    const target = host + ":" + node.targetPort;

    return pattern + " -> " + target;
}

function serialize(config) {
    return config.nodes.map(lineFor).join(config.eol || "\n");
}

// Resolve the parsed nodes into runtime route lists for the proxy server.
function toRuntime(config, opts) {
    opts = opts || {};
    const forwardHost = opts.forwardHost;

    const routes = config.nodes
        .filter((n) => n.t === "route")
        .map((n) => ({
            ws: n.ws,
            pathPrefix: n.pathPrefix || "",
            // FORWARD_HOST env overrides the default host, but never an explicit one.
            host: forwardHost && n.targetHost === DEFAULT_HOST ? forwardHost : n.targetHost,
            port: n.targetPort,
        }));

    return {
        web: routes.filter((r) => !r.ws),
        ws: routes.filter((r) => r.ws),
    };
}

// Seed proxy.conf into a writable location (userData) on first run, copying the
// bundled default. Returns the path of the writable config file.
function ensureConfigFile(userDataDir, bundledDir) {
    const target = path.join(userDataDir, "proxy.conf");
    if (!fs.existsSync(target)) {
        let content = DEFAULT_PROXY_CONF;
        try {
            const bundled = path.join(bundledDir, "proxy.conf");
            if (fs.existsSync(bundled)) content = fs.readFileSync(bundled, "utf8");
        } catch (_) {
            /* fall back to DEFAULT_PROXY_CONF */
        }
        fs.writeFileSync(target, content, "utf8");
    }
    return target;
}

module.exports = { parse, serialize, toRuntime, ensureConfigFile, DEFAULT_PROXY_CONF, DEFAULT_HOST };
