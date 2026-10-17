// Stands in for the Electron preload: exposes window.hostsAPI and
// window.proxyAPI backed by the local Hosts Tray server. The access token
// arrives in the URL fragment (never sent to servers or logged) and is kept
// for this tab only.
(function () {
    const m = location.hash.match(/token=([0-9a-f]+)/);
    if (m) {
        sessionStorage.setItem("hoststray-token", m[1]);
        history.replaceState(null, "", location.pathname);
    }

    async function call(method, path, body) {
        const res = await fetch(path, {
            method,
            headers: {
                "Content-Type": "application/json",
                "X-Hoststray-Token": sessionStorage.getItem("hoststray-token") || "",
            },
            body: body === undefined ? undefined : JSON.stringify(body),
        });
        if (res.status === 401) {
            document.body.innerHTML = '<p style="font:15px system-ui;padding:2em">This editor link has expired. ' +
                "Open it again from the Hosts Tray menu.</p>";
            throw new Error("unauthorized");
        }
        const data = await res.json();
        if (!res.ok && !("ok" in data)) throw new Error(data.error || res.statusText);
        return data;
    }

    window.hostsAPI = {
        load: () => call("GET", "/api/hosts"),
        save: (doc) => call("POST", "/api/hosts", doc),
    };
    window.proxyAPI = {
        load: () => call("GET", "/api/proxy"),
        save: (config) => call("POST", "/api/proxy", config),
    };
})();
