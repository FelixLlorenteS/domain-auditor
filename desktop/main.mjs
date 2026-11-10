/**
 * Domain Auditor desktop app (Windows and Linux). It shows the same build as
 * the website, served from the app's own `app://` scheme, and adds a network
 * probe (probe.mjs) for the checks a browser cannot make: HTTP headers, TLS and
 * files served without CORS.
 *
 * Hardening: context isolation and the sandbox are on, Node.js is off in the
 * page, navigation never leaves the app, external links open in the system
 * browser, and the IPC handlers validate every argument.
 */
import { app, BrowserWindow, dialog, ipcMain, Menu, net, protocol, shell } from "electron";
import { writeFile } from "node:fs/promises";
import { dirname, join, normalize, sep } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";
import { request, tlsProbe } from "./probe.mjs";

const here = dirname(fileURLToPath(import.meta.url));
const DIST = join(here, "..", "dist");
const ORIGIN = "app://domain-auditor";

protocol.registerSchemesAsPrivileged([{ scheme: "app", privileges: { standard: true, secure: true, supportFetchAPI: true } }]);

// End-to-end tests run with their own profile, apart from the user's.
if (process.env.DOMAIN_AUDITOR_USER_DATA) app.setPath("userData", process.env.DOMAIN_AUDITOR_USER_DATA);
if (!app.requestSingleInstanceLock()) app.quit();

/** Files of the build, by path; folders serve their index.html. Nothing outside dist/. */
function serve(req) {
  const { pathname } = new URL(req.url);
  let rel = decodeURIComponent(pathname);
  if (rel.endsWith("/")) rel += "index.html";
  const file = normalize(join(DIST, rel));
  if (!file.startsWith(DIST + sep)) return new Response("Not found", { status: 404 });
  return net.fetch(pathToFileURL(file).toString());
}

let win;

function createWindow() {
  win = new BrowserWindow({
    width: 1320,
    height: 900,
    minWidth: 380,
    minHeight: 500,
    show: false,
    backgroundColor: "#090909",
    title: "Domain Auditor",
    icon: join(here, "icon.png"),
    autoHideMenuBar: true,
    webPreferences: {
      preload: join(here, "preload.cjs"),
      contextIsolation: true,
      sandbox: true,
      nodeIntegration: false,
      webSecurity: true,
      spellcheck: false,
      // An audit keeps its pace while the user works in another window.
      backgroundThrottling: false,
      additionalArguments: [`--app-version=${app.getVersion()}`],
    },
  });
  win.once("ready-to-show", () => win.show());
  // Links to other tools (VirusTotal, internet.nl…) open in the user's browser.
  win.webContents.setWindowOpenHandler(({ url }) => {
    if (/^https:\/\//.test(url)) shell.openExternal(url);
    return { action: "deny" };
  });
  win.webContents.on("will-navigate", (e, url) => {
    if (url.startsWith(`${ORIGIN}/`)) return;
    e.preventDefault();
    if (/^https:\/\//.test(url)) shell.openExternal(url);
  });
  win.webContents.on("will-attach-webview", (e) => e.preventDefault());
  win.loadURL(`${ORIGIN}/`);
}

ipcMain.handle("web:request", (_e, url) => request(String(url)));
ipcMain.handle("web:tls", (_e, host, version) => tlsProbe(String(host), version === undefined || version === null ? undefined : String(version)));

/** The client report as a PDF file, chosen by the user. The page is already in print mode. */
ipcMain.handle("report:pdf", async (e, fileName) => {
  const owner = BrowserWindow.fromWebContents(e.sender);
  const safeName = String(fileName).replace(/[^\w.@-]+/g, "_").slice(0, 120) || "informe.pdf";
  const name = safeName.endsWith(".pdf") ? safeName : `${safeName}.pdf`;
  // End-to-end tests (tests/e2e/desktop.mjs) save to a folder without the dialog.
  const testDir = process.env.DOMAIN_AUDITOR_PDF_DIR;
  const { canceled, filePath } = testDir
    ? { canceled: false, filePath: join(testDir, name) }
    : await dialog.showSaveDialog(owner, { defaultPath: join(app.getPath("documents"), name), filters: [{ name: "PDF", extensions: ["pdf"] }] });
  if (canceled || !filePath) return { saved: false };
  const pdf = await e.sender.printToPDF({ pageSize: "A4", printBackground: true, preferCSSPageSize: true });
  await writeFile(filePath, pdf);
  if (!testDir) shell.openPath(filePath);
  return { saved: true, path: filePath };
});

app.on("second-instance", () => {
  if (win) {
    if (win.isMinimized()) win.restore();
    win.focus();
  }
});

app.whenReady().then(() => {
  Menu.setApplicationMenu(null);
  protocol.handle("app", serve);
  createWindow();
});

app.on("window-all-closed", () => app.quit());
