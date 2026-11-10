/**
 * The only bridge between the page and the main process: three functions, with
 * arguments checked again on the other side. The page gets no Node.js access.
 */
const { contextBridge, ipcRenderer } = require("electron");

/** A probe answer of `{ error }` becomes an exception with that code, like fetch(). */
const unwrap = (r) => {
  if (r && r.error) {
    const e = new Error(r.error);
    e.code = r.error;
    throw e;
  }
  return r;
};

contextBridge.exposeInMainWorld("desktop", {
  version: (process.argv.find((a) => a.startsWith("--app-version=")) || "").slice("--app-version=".length),
  platform: process.platform,
  request: async (url) => unwrap(await ipcRenderer.invoke("web:request", String(url))),
  tls: async (host, version) => unwrap(await ipcRenderer.invoke("web:tls", String(host), version === undefined ? undefined : String(version))),
  savePdf: (fileName) => ipcRenderer.invoke("report:pdf", String(fileName)),
});
