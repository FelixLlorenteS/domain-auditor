/**
 * End-to-end test of the desktop app, against the live Internet: it starts the
 * app as a user would, audits a real domain and checks what reaches the screen
 * and the PDF. It catches what unit tests cannot (a blank PDF, a broken bridge,
 * a script error). Usage: `pnpm e2e [domain]` (default felixllorente.com).
 * No dependencies: the app is driven through the Chrome DevTools Protocol.
 */
import { spawn, execFileSync } from "node:child_process";
import { existsSync, mkdtempSync, readdirSync, rmSync, statSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import electronPath from "electron";

const domain = process.argv[2] ?? "felixllorente.com";
const PORT = 9400 + Math.floor(Math.random() * 400);
const work = mkdtempSync(join(tmpdir(), "da-e2e-"));
const pdfDir = join(work, "pdf");
execFileSync("mkdir", ["-p", pdfDir]);

const app = spawn(electronPath, [".", `--remote-debugging-port=${PORT}`], {
  env: { ...process.env, DOMAIN_AUDITOR_PDF_DIR: pdfDir, DOMAIN_AUDITOR_USER_DATA: join(work, "profile") },
  stdio: "ignore",
});
const results = [];
const check = (name, ok, detail = "") => {
  results.push({ name, ok });
  console.log(`${ok ? "✓" : "✗"} ${name}${detail ? ` — ${detail}` : ""}`);
};
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

async function connect() {
  for (let i = 0; i < 60; i++) {
    try {
      const page = (await (await fetch(`http://127.0.0.1:${PORT}/json`)).json()).find((p) => p.type === "page" && p.url.startsWith("app://"));
      if (page) return page.webSocketDebuggerUrl;
    } catch {
      /* not up yet */
    }
    await sleep(500);
  }
  throw new Error("the app did not start");
}

try {
  const ws = new WebSocket(await connect());
  let id = 0;
  const pending = new Map();
  const errors = [];
  ws.onmessage = (m) => {
    const d = JSON.parse(m.data);
    if (d.id && pending.has(d.id)) {
      pending.get(d.id)(d);
      pending.delete(d.id);
    } else if (d.method === "Runtime.exceptionThrown") errors.push(d.params.exceptionDetails.exception?.description ?? d.params.exceptionDetails.text);
  };
  await new Promise((r) => (ws.onopen = r));
  const send = (method, params = {}) =>
    new Promise((r) => {
      const i = ++id;
      pending.set(i, r);
      ws.send(JSON.stringify({ id: i, method, params }));
    });
  const ev = async (expression) => (await send("Runtime.evaluate", { expression, awaitPromise: true, returnByValue: true })).result?.result?.value;
  await send("Runtime.enable");

  // 1. The app and its bridge
  check("la app carga su página", (await ev("document.title")).includes("Domain Auditor"));
  check("puente de escritorio disponible", await ev("typeof window.desktop?.request === 'function' && typeof window.desktop?.tls === 'function'"));
  check("insignia de escritorio visible", await ev("!!document.querySelector('.desktop-badge')"));
  check("la página no tiene Node.js", await ev("typeof require === 'undefined' && typeof process === 'undefined'"));

  // 2. The probe refuses what it must
  const blocked = await ev("window.desktop.request('http://localtest.me/').then(() => 'answered', (e) => e.message)");
  check("no se conecta a direcciones privadas", blocked === "BLOCKED_PRIVATE_ADDRESS", `localtest.me → ${blocked}`);
  const bad = await ev("window.desktop.request('file:///etc/passwd').then(() => 'answered', (e) => e.message)");
  check("rechaza esquemas que no son http(s)", bad === "BAD_URL", bad);

  // 3. A real audit
  const started = Date.now();
  await send("Page.navigate", { url: `app://domain-auditor/?q=${domain}` });
  let first = 0;
  for (let i = 0; i < 240; i++) {
    await sleep(250);
    if (!first && (await ev("!!document.querySelector('.toolbar')"))) first = Date.now() - started;
    if (first && (await ev("!document.querySelector('#submit').disabled"))) break;
  }
  const total = Date.now() - started;
  check("primer informe en menos de 8 s", first > 0 && first < 8_000, `${(first / 1000).toFixed(1)} s`);
  // When it is slow, say which requests took longest (from the raw data view).
  if (!first || first >= 8_000) {
    await ev("document.querySelector('[data-act=raw]').click()");
    await sleep(800);
    const slow = await ev(`[...document.querySelectorAll('main *')]
      .filter((e) => e.children.length === 0 && /\\d\\s?ms$/.test(e.textContent.trim()))
      .map((e) => (e.closest('details,li,tr') || e.parentElement).innerText.replace(/\\n/g, ' ').slice(0, 110))
      .sort((a, b) => parseInt(b.match(/(\\d+)\\s?ms/)[1]) - parseInt(a.match(/(\\d+)\\s?ms/)[1]))
      .slice(0, 5)`);
    for (const line of slow ?? []) console.log(`    · ${line}`);
    await ev("document.querySelector('[data-act=report]').click()");
    await sleep(500);
  }
  check("informe completo en menos de 40 s", total < 40_000, `${(total / 1000).toFixed(1)} s`);
  const verdicts = await ev("[...document.querySelectorAll('.verdict')].map(v => v.querySelector('.verdict-area')?.textContent)");
  check("veredicto de la web", (verdicts ?? []).includes("Web"), (verdicts ?? []).join(", "));
  const web = await ev("[...document.querySelectorAll('#g-web .control')].map(c => c.id + ':' + c.dataset.state)");
  check("controles web (HTTPS, TLS, cabeceras, security.txt)", (web ?? []).length === 4, (web ?? []).join(" "));
  check("sin «Consultando…» al terminar", !(await ev("document.body.innerText.includes('Consultando Certificate Transparency')")));

  // 4. The client report as a PDF
  await ev("document.querySelector('[data-act=print]').click()");
  let pdf;
  for (let i = 0; i < 60 && !pdf; i++) {
    await sleep(500);
    pdf = readdirSync(pdfDir).find((f) => f.endsWith(".pdf"));
  }
  check("se guarda el PDF", Boolean(pdf), pdf ?? "");
  if (pdf) {
    const file = join(pdfDir, pdf);
    await sleep(500);
    const pages = Number(/Pages:\s+(\d+)/.exec(execFileSync("pdfinfo", [file]).toString())?.[1] ?? 0);
    const text = execFileSync("pdftotext", ["-layout", file, "-"]).toString();
    check("el PDF tiene contenido", statSync(file).size > 20_000 && pages >= 3, `${pages} páginas, ${Math.round(statSync(file).size / 1024)} KB`);
    check("el PDF es el informe para cliente", text.includes("Resumen ejecutivo") && text.includes("Plan de acción") && text.includes(domain));
    check("el PDF no arrastra la interfaz", !text.includes("Detalle técnico") && !text.includes("Ver datos en crudo"));
  }
  check("la página vuelve a su estado tras el PDF", !(await ev("document.documentElement.classList.contains('printing-report')")));

  // 5. Raw data
  await ev("document.querySelector('[data-act=raw]').click()");
  await sleep(800);
  check("los datos en crudo incluyen las conexiones a la web", await ev("document.body.innerText.includes('Web (HTTPS/TLS)')"));

  check("sin errores de JavaScript", errors.length === 0, errors.slice(0, 2).join(" | "));
  ws.close();
} catch (err) {
  check("la prueba se completó", false, String(err));
} finally {
  app.kill();
  if (existsSync(work)) rmSync(work, { recursive: true, force: true });
}

const failed = results.filter((r) => !r.ok).length;
console.log(`\n${results.length - failed}/${results.length} comprobaciones superadas`);
process.exit(failed ? 1 : 0);
