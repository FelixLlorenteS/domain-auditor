/**
 * Links to other tools for the same domain or IP. Nothing is queried: each one
 * opens only if the person clicks it, so the page stays serverless and keyless.
 * They cover what the browser cannot read (VirusTotal and AbuseIPDB send no CORS,
 * SSL Labs tests TLS) or offer a second opinion (internet.nl, DNSViz).
 */
import type { Report } from "../core/types";
import type { Lang } from "../i18n";

export interface ExternalLink {
  name: string;
  url: string;
  /** What that tool adds, in a few words. */
  what: string;
}

type Texts = Record<string, string>;

const TEXT: Record<Lang, Texts> = {
  es: {
    title: "Ver en otras herramientas",
    note: "Se abren en otra pestaña y sólo si pulsas: cada servicio recibe el dominio o la IP.",
    virustotal: "Reputación según decenas de antivirus y listas",
    abuseipdb: "Denuncias de abuso de la IP",
    nlSite: "Prueba de la web: IPv6, DNSSEC, HTTPS, cabeceras",
    nlMail: "Prueba del correo: SPF, DKIM, DMARC, STARTTLS, DANE",
    ssllabs: "Certificado y configuración TLS de la web",
    dnsviz: "Cadena DNSSEC paso a paso",
    mxtoolbox: "Listas negras de correo",
    shodan: "Servicios expuestos de la IP",
    otx: "Pulsos de la comunidad",
  },
  en: {
    title: "See in other tools",
    note: "They open in another tab and only when clicked: each service receives the domain or the IP.",
    virustotal: "Reputation across dozens of antivirus engines and lists",
    abuseipdb: "Abuse reports for the IP",
    nlSite: "Website test: IPv6, DNSSEC, HTTPS, headers",
    nlMail: "E-mail test: SPF, DKIM, DMARC, STARTTLS, DANE",
    ssllabs: "The website's certificate and TLS setup",
    dnsviz: "DNSSEC chain step by step",
    mxtoolbox: "Mail blocklists",
    shodan: "Services exposed on the IP",
    otx: "Community pulses",
  },
};

export function externalTitle(lang: Lang): { title: string; note: string } {
  return { title: TEXT[lang].title!, note: TEXT[lang].note! };
}

/** Links for a report: by domain, plus by its first address (the website's) when there is one. */
export function externalLinks(report: Report, lang: Lang): ExternalLink[] {
  const t = TEXT[lang];
  const q = encodeURIComponent(report.query);
  if (report.kind === "ip") {
    if (report.identity?.special) return [];
    return [
      { name: "VirusTotal", url: `https://www.virustotal.com/gui/ip-address/${q}`, what: t.virustotal! },
      { name: "AbuseIPDB", url: `https://www.abuseipdb.com/check/${q}`, what: t.abuseipdb! },
      { name: "Shodan", url: `https://www.shodan.io/host/${q}`, what: t.shodan! },
      { name: "AlienVault OTX", url: `https://otx.alienvault.com/indicator/ip/${q}`, what: t.otx! },
    ];
  }
  const ip = report.identity?.hostingIp ? encodeURIComponent(report.identity.hostingIp) : undefined;
  const links: ExternalLink[] = [
    { name: "VirusTotal", url: `https://www.virustotal.com/gui/domain/${q}`, what: t.virustotal! },
    { name: "internet.nl", url: `https://internet.nl/site/${q}/`, what: t.nlSite! },
    { name: "internet.nl", url: `https://internet.nl/mail/${q}/`, what: t.nlMail! },
    { name: "SSL Labs", url: `https://www.ssllabs.com/ssltest/analyze.html?d=${q}`, what: t.ssllabs! },
    { name: "DNSViz", url: `https://dnsviz.net/d/${q}/dnssec/`, what: t.dnsviz! },
    { name: "MXToolbox", url: `https://mxtoolbox.com/SuperTool.aspx?action=blacklist%3a${q}`, what: t.mxtoolbox! },
    { name: "AlienVault OTX", url: `https://otx.alienvault.com/indicator/domain/${q}`, what: t.otx! },
  ];
  // Behind a CDN the first address is the provider's: its abuse reports say nothing of the domain.
  if (ip && !report.identity?.cdn) links.push({ name: "AbuseIPDB", url: `https://www.abuseipdb.com/check/${ip}`, what: t.abuseipdb! });
  return links;
}
