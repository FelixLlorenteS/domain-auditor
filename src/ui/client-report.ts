/**
 * The client report: a document of its own, not the web page printed. Always the
 * same structure, written for whoever has to act on it:
 *   1. Executive summary: score, verdict per area, priorities, who it is.
 *   2. Status of every control, in one table.
 *   3. Action plan: only what needs fixing, worst first, with the exact record.
 *   4. Annex: what is fine, what could not be verified, sources.
 * It reuses the report's findings and texts: nothing is re-evaluated here.
 */
import { verdicts, type Verdict } from "../core/summary";
import type { Finding, Report } from "../core/types";
import { message, verdictText, type Lang, type MessageContext } from "../i18n";
import { ATTACK_NOTICE, riskOf } from "./attack";
import { buildControls, needsAction, scoreOf, severityOf, TEXT as CTEXT, type Control } from "./controls";
import { escapeHtml, rich } from "./layout";

const TEXT = {
  es: {
    title: "Informe de seguridad del dominio",
    prepared: "Preparado con Domain Auditor a partir de consultas públicas en vivo",
    summary: "1. Resumen ejecutivo",
    score: "{passed} de {total} controles básicos bien",
    extras: "Mejoras opcionales: {extras} de {extrasTotal}",
    actions: "{n} acciones recomendadas",
    noActions: "Sin acciones pendientes",
    priorities: "Prioridades",
    prioritiesNone: "No hay nada que corregir en los controles evaluados.",
    who: "Quién es",
    status: "2. Estado de los controles",
    colArea: "Área",
    colControl: "Control",
    colState: "Estado",
    colSeverity: "Severidad",
    colSummary: "Resumen",
    plan: "3. Plan de acción",
    planNone: "No hay acciones pendientes.",
    problem: "Qué pasa",
    risk: "Riesgo",
    fix: "Cómo arreglarlo",
    records: "Registro exacto",
    reference: "Referencia",
    annex: "4. Anexo",
    fine: "Lo que está bien",
    unverified: "Lo que no se pudo verificar",
    method: "Metodología y fuentes",
    methodText:
      "Revisión externa y automática: sólo se usan datos públicos (DNS, registro del dominio, Certificate Transparency y servicios de reputación), consultados en vivo el día del informe. No se accede a los servidores del dominio ni se conoce su contexto interno: antes de aplicar un cambio, compruébalo con quien gestiona el dominio. Cada resultado cita la norma (RFC) en que se basa.",
    methodTextWeb:
      "Revisión externa y automática: datos públicos (DNS, registro del dominio, Certificate Transparency y servicios de reputación) y una visita a la web del dominio como la de un navegador (HTTP, HTTPS, TLS y cabeceras de la página de inicio), todo en vivo el día del informe. No se prueba ninguna vulnerabilidad ni se conoce el contexto interno: antes de aplicar un cambio, compruébalo con quien gestiona el dominio. Cada resultado cita la norma (RFC) en que se basa.",
    levels: { good: "Bien", partial: "Mejorable", bad: "Riesgo", unknown: "Sin datos" },
    mailbox: "<buzón>",
  },
  en: {
    title: "Domain security report",
    prepared: "Prepared with Domain Auditor from live public queries",
    summary: "1. Executive summary",
    score: "{passed} of {total} basic controls fine",
    extras: "Optional hardening: {extras} of {extrasTotal}",
    actions: "{n} recommended actions",
    noActions: "No pending actions",
    priorities: "Priorities",
    prioritiesNone: "Nothing to fix in the controls assessed.",
    who: "Who it is",
    status: "2. Status of the controls",
    colArea: "Area",
    colControl: "Control",
    colState: "Status",
    colSeverity: "Severity",
    colSummary: "Summary",
    plan: "3. Action plan",
    planNone: "No pending actions.",
    problem: "What is wrong",
    risk: "Risk",
    fix: "How to fix it",
    records: "Exact record",
    reference: "Reference",
    annex: "4. Annex",
    fine: "What is fine",
    unverified: "What could not be verified",
    method: "Method and sources",
    methodText:
      "External, automated review: only public data is used (DNS, domain registration, Certificate Transparency and reputation services), queried live on the day of the report. The domain's servers are not accessed and its internal context is unknown: before applying a change, check it with whoever runs the domain. Each result cites the standard (RFC) it is based on.",
    methodTextWeb:
      "External, automated review: public data (DNS, domain registration, Certificate Transparency and reputation services) and a visit to the domain's website like a browser's (HTTP, HTTPS, TLS and the home page's headers), all live on the day of the report. No vulnerability is tested and the internal context is unknown: before applying a change, check it with whoever runs the domain. Each result cites the standard (RFC) it is based on.",
    levels: { good: "Good", partial: "Improvable", bad: "Risk", unknown: "No data" },
    mailbox: "<mailbox>",
  },
} as const;

/** The finding that best names a control: its worst one that is not a plain "found". */
function headline(c: Control): Finding {
  const top = c.findings.filter(({ f }) => f.status === c.findings[0]!.f.status).map(({ f }) => f);
  return top.find((f) => !f.id.endsWith(".found")) ?? top[0]!;
}

const SEV_RANK = { high: 0, medium: 1, low: 2 } as const;

/** "Severidad alta" → "Alta" in the table, whose column already says "Severity". */
const shortSeverity = (label: string) => {
  const word = label.replace(/^(severidad|severity)\s+/i, "").replace(/\s+severity$/i, "");
  return word.charAt(0).toUpperCase() + word.slice(1);
};

export function clientReportHtml(report: Report, lang: Lang, identity: Array<[string, string]>, ctx: MessageContext): string {
  const t = TEXT[lang];
  const x = CTEXT[lang];
  const groups = buildControls(report);
  const controls = groups.flatMap((g) => g.controls.map((c) => ({ c, group: x.groups[g.id] })));
  const score = scoreOf(report, groups);
  const todo = controls.filter(({ c }) => needsAction(c)).sort((a, b) => SEV_RANK[severityOf(a.c)] - SEV_RANK[severityOf(b.c)]);
  const msg = (f: Finding) => message(lang, f.id, f.params, ctx);
  const date = new Date(report.generatedAt).toLocaleString(lang === "es" ? "es-ES" : "en-GB");
  const fill = (s: string, v: Record<string, string | number>) => s.replace(/\{(\w+)\}/g, (_, k: string) => String(v[k] ?? ""));

  // 1. Executive summary
  const verdictCards = verdicts(report)
    .map((v: Verdict) => {
      const vt = verdictText(lang, v);
      return `<div class="cr-verdict l-${v.level}"><strong>${escapeHtml(vt.title)}</strong><span>${t.levels[v.level]}</span><p>${rich(vt.text)}</p></div>`;
    })
    .join("");
  const priorities = todo
    .slice(0, 5)
    .map(({ c }) => `<li><strong>${x.controls[c.id] ?? c.id}</strong> · ${rich(msg(headline(c)).title)} <em>(${x.severity[severityOf(c)]})</em></li>`)
    .join("");
  const who = identity.map(([k, v]) => `<tr><th>${escapeHtml(k)}</th><td>${escapeHtml(v)}</td></tr>`).join("");

  // 2. Status table
  const rows = controls
    .map(
      ({ c, group }) =>
        `<tr class="st-${c.state}"><td>${group}</td><td>${x.controls[c.id] ?? c.id}</td><td>${x.states[c.state]}</td><td>${needsAction(c) ? shortSeverity(x.severity[severityOf(c)]) : "—"}</td><td>${rich(msg(headline(c)).title)}</td></tr>`,
    )
    .join("");

  // 3. Action plan
  const plan = todo
    .map(({ c }, i) => {
      const problems = c.findings.map(({ f }) => f).filter((f) => f.status === "fail" || f.status === "warn");
      const steps = [...new Set(problems.flatMap((f) => msg(f).steps ?? []))];
      const records = problems.flatMap((f) => f.suggest ?? []);
      const risk = riskOf(c.id, false, lang);
      const refs = [...new Set(problems.map((f) => msg(f).tech?.match(/RFC \d+(, sección [\d.]+| section [\d.]+)?/)?.[0]).filter(Boolean))];
      return `
        <section class="cr-action">
          <h3>${i + 1}. ${x.controls[c.id] ?? c.id} <span class="cr-sev sev-${severityOf(c)}">${x.severity[severityOf(c)]}</span></h3>
          <h4>${t.problem}</h4>
          ${problems.map((f) => `<p><strong>${rich(msg(f).title)}.</strong> ${rich(msg(f).what ?? "")}</p>`).join("")}
          ${risk ? `<h4>${t.risk}</h4><p>${rich(risk.text)}</p>` : ""}
          ${steps.length ? `<h4>${t.fix}</h4><ol>${steps.map((s) => `<li>${rich(s)}</li>`).join("")}</ol>` : ""}
          ${
            records.length
              ? `<h4>${t.records}</h4><table class="cr-records">${records
                  .map((r) => `<tr><td>${escapeHtml(r.type)}</td><td>${escapeHtml(r.name)}</td><td><code>${escapeHtml(r.value.replace("{mailbox}", t.mailbox))}</code></td></tr>`)
                  .join("")}</table>`
              : ""
          }
          ${refs.length ? `<p class="cr-ref">${t.reference}: ${refs.map((r) => escapeHtml(r!)).join(" · ")}</p>` : ""}
        </section>`;
    })
    .join("");

  // 4. Annex
  const list = (items: typeof controls) => items.map(({ c }) => `<li><strong>${x.controls[c.id] ?? c.id}</strong> · ${rich(msg(headline(c)).title)}</li>`).join("");
  const fine = controls.filter(({ c }) => c.state === "ok");
  const unknown = controls.filter(({ c }) => c.state === "unknown");
  const usesAttack = todo.some(({ c }) => (riskOf(c.id, false, lang)?.techniques.length ?? 0) > 0);

  return `
    <article class="client-report" lang="${lang}">
      <header class="cr-cover">
        <p class="cr-kicker">${t.title}</p>
        <h1>${escapeHtml(report.query)}</h1>
        <p>${escapeHtml(date)} · ${t.prepared}</p>
      </header>

      <section class="cr-section">
        <h2>${t.summary}</h2>
        <div class="cr-metrics">
          <div><strong>${score.total ? fill(t.score, { passed: score.passed, total: score.total }) : "—"}</strong>${score.extrasTotal ? `<span>${fill(t.extras, { extras: score.extras, extrasTotal: score.extrasTotal })}</span>` : ""}</div>
          <div><strong>${todo.length ? fill(t.actions, { n: todo.length }) : t.noActions}</strong></div>
        </div>
        <div class="cr-verdicts">${verdictCards}</div>
        <h3>${t.priorities}</h3>
        ${priorities ? `<ol class="cr-priorities">${priorities}</ol>` : `<p>${t.prioritiesNone}</p>`}
        ${who ? `<h3>${t.who}</h3><table class="cr-who">${who}</table>` : ""}
      </section>

      <section class="cr-section cr-break">
        <h2>${t.status}</h2>
        <table class="cr-status">
          <thead><tr><th>${t.colArea}</th><th>${t.colControl}</th><th>${t.colState}</th><th>${t.colSeverity}</th><th>${t.colSummary}</th></tr></thead>
          <tbody>${rows}</tbody>
        </table>
      </section>

      <section class="cr-section cr-break">
        <h2>${t.plan}</h2>
        ${plan || `<p>${t.planNone}</p>`}
      </section>

      <section class="cr-section cr-break">
        <h2>${t.annex}</h2>
        ${fine.length ? `<h3>${t.fine}</h3><ul>${list(fine)}</ul>` : ""}
        ${unknown.length ? `<h3>${t.unverified}</h3><ul>${list(unknown)}</ul>` : ""}
        <h3>${t.method}</h3>
        <p>${report.sections.some((s) => s.id === "web") ? t.methodTextWeb : t.methodText}</p>
        ${usesAttack ? `<p class="cr-ref">${escapeHtml(ATTACK_NOTICE)}</p>` : ""}
      </section>
    </article>`;
}
