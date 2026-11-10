/**
 * Third parties the domain is tied to, read from what the domain itself
 * publishes: TXT verification tokens (each one proves the domain was added to
 * a service) and the `include:` of SPF (services allowed to send its mail).
 * Names are only given for services whose token or SPF domain is documented by
 * the service; anything else is listed as it appears, never guessed.
 */

const VERIFICATIONS: Array<[RegExp, string]> = [
  [/^google-site-verification=/i, "Google (Search Console / Workspace)"],
  [/^MS=ms\d+/, "Microsoft 365"],
  [/^facebook-domain-verification=/i, "Meta (Facebook)"],
  [/^atlassian-domain-verification=/i, "Atlassian"],
  [/^apple-domain-verification=/i, "Apple"],
  [/^docusign=/i, "DocuSign"],
  [/^adobe-idp-site-verification=/i, "Adobe"],
  [/^globalsign-domain-verification=/i, "GlobalSign"],
  [/^stripe-verification=/i, "Stripe"],
  [/^openai-domain-verification=/i, "OpenAI"],
  [/^have-i-been-pwned-verification=/i, "Have I Been Pwned"],
  [/^cisco-ci-domain-verification=/i, "Cisco Webex"],
  [/^dropbox-domain-verification=/i, "Dropbox"],
  [/^slack-domain-verification=/i, "Slack"],
  [/^yandex-verification:/i, "Yandex"],
  [/^onetrust-domain-verification=/i, "OneTrust"],
  [/^amazonses:/i, "Amazon SES"],
  [/^(brevo|sendinblue)-code:/i, "Brevo"],
];

/** Generic shape of a verification token: `<service>-verification=…`, `<service>-domain-verification=…`. */
const GENERIC = /^([a-z0-9][a-z0-9._-]*?)[-_](?:site[-_]|domain[-_])?verification[=:]/i;

const SENDERS: Array<[RegExp, string]> = [
  [/^_spf\.google\.com$/, "Google Workspace"],
  [/^spf\.protection\.outlook\.com$/, "Microsoft 365"],
  [/^_spf\.mx\.cloudflare\.net$/, "Cloudflare Email Routing"],
  [/^sendgrid\.net$/, "SendGrid"],
  [/^mailgun\.org$/, "Mailgun"],
  [/^amazonses\.com$/, "Amazon SES"],
  [/^servers\.mcsv\.net$/, "Mailchimp"],
  [/^spf\.mandrillapp\.com$/, "Mandrill"],
  [/^_spf\.salesforce\.com$/, "Salesforce"],
  [/^zoho\.(com|eu|in)$/, "Zoho Mail"],
  [/^spf\.brevo\.com$|^spf\.sendinblue\.com$/, "Brevo"],
  [/^_spf\.protonmail\.ch$/, "Proton Mail"],
  [/\.pphosted\.com$/, "Proofpoint"],
];

export interface Integration {
  service: string;
  /** What it was read from: the start of the token or the SPF domain. */
  source: string;
}

export function verificationsOf(txt: string[]): Integration[] {
  const out: Integration[] = [];
  for (const value of txt) {
    const known = VERIFICATIONS.find(([re]) => re.test(value));
    const token = value.split(/[=:]/)[0] ?? value;
    if (known) out.push({ service: known[1], source: `${token}=` });
    else {
      const generic = GENERIC.exec(value);
      if (generic) out.push({ service: generic[1]!, source: `${token}=` });
    }
  }
  return dedupe(out);
}

export function sendersOf(spf: string | undefined): Integration[] {
  if (!spf) return [];
  // Macro labels (`%{ir}.%{d}.`) are dropped: the service is the fixed part after them.
  const includes = [...spf.matchAll(/\binclude:([^\s]+)/gi)].map((m) => m[1]!.toLowerCase().replace(/^(?:[^.]*%\{[^}]*\}[^.]*\.)+/, ""));
  return dedupe(includes.map((d) => ({ service: SENDERS.find(([re]) => re.test(d))?.[1] ?? d, source: `include:${d}` })));
}

function dedupe(list: Integration[]): Integration[] {
  const seen = new Set<string>();
  return list.filter((i) => (seen.has(i.service) ? false : (seen.add(i.service), true)));
}
