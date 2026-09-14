const { contextBridge, ipcRenderer } = require("electron");

contextBridge.exposeInMainWorld("hostsAPI", {
    load: () => ipcRenderer.invoke("hosts:load"),
    save: (doc) => ipcRenderer.invoke("hosts:save", doc),
});

contextBridge.exposeInMainWorld("proxyAPI", {
    load: () => ipcRenderer.invoke("proxy:load"),
    save: (config) => ipcRenderer.invoke("proxy:save", config),
});
