/** Result of a single check. Texts live in src/i18n.ts, keyed by `id`. */
export type Status = "ok" | "warn" | "fail" | "info";

export type Params = Record<string, string | number>;

/** A DNS record the user can copy into their DNS panel to fix a finding. */
export interface Suggestion {
  type: string;
  /** Fully qualified name, e.g. `_dmarc.example.com`. */
  name: string;
  value: string;
  /** `replace`: an existing record of the same purpose must be replaced, not added. */
  action?: "add" | "replace";
  /** The value contains `{mailbox}`: the user must type a mailbox that exists. */
  input?: "mailbox";
  optional?: boolean;
}

/** A file the user must publish (e.g. the MTA-STS policy), generated from real data. */
export interface SuggestedFile {
  url: string;
  content: string;
}

export interface Finding {
  id: string;
  status: Status;
  params?: Params;
  suggest?: Suggestion[];
  files?: SuggestedFile[];
}

export interface RecordRow {
  name: string;
  type: string;
  ttl?: number;
  data: string;
  /** Set when the name came from another source than a direct query (e.g. `ct`). */
  source?: "ct";
}

export type SectionId = "mail" | "dns" | "web" | "registration" | "ip";

export interface Section {
  id: SectionId;
  findings: Finding[];
  records: RecordRow[];
}

/** The same query answered by both resolvers. */
export interface ResolverCheck {
  name: string;
  type: string;
  providers: [string, string];
  answers: [string[], string[]];
  same: boolean;
  /** DNSSEC validation (AD bit) reported by each resolver. */
  ad: [boolean, boolean];
}

/**
 * Who the target belongs to, shown first in the report. Every field comes from a
 * live query (PTR, RDAP, RIPEstat, NS/MX names); nothing is taken from a fixed list.
 */
export interface Identity {
  /** IP: reverse name (PTR). */
  ptr?: string;
  /** IP: holder of the address block (RDAP). Domain: registrant organisation. */
  holder?: string;
  /** Domain: the registrar hides the registrant. */
  holderRedacted?: boolean;
  /** Network that announces the IP in BGP (RIPEstat). */
  asn?: number;
  asHolder?: string;
  prefix?: string;
  network?: string;
  range?: string;
  country?: string;
  special?: string;
  registrar?: string;
  created?: string;
  registeredDomain?: string;
  dnsProvider?: string;
  /** Name servers as published, for when the provider is not recognised. */
  nsHosts?: string[];
  mailProvider?: string;
  mxHosts?: string[];
  noMail?: boolean;
  /** Domain: where the website is hosted (AS of its first address). */
  hostingIp?: string;
  hostingAsn?: number;
  hostingHolder?: string;
  /**
   * Whether the domain uses mail, deduced from what it publishes:
   * - disabled: null MX, or an SPF that authorises nobody (`v=spf1 -all`);
   * - active: real MX, an SPF that authorises senders, or a DKIM key found;
   * - unknown: none of the above (no MX and no SPF).
   * Recommendations depend on it, so an inference never becomes advice that
   * could break legitimate mail.
   */
  mailUsage?: "active" | "disabled" | "unknown";
  /** Proxy/CDN in front of the website (its addresses belong to it), not the origin. */
  cdn?: string;
  /**
   * Where the IP (or the website's first address) is located, from RIPEstat
   * geolocation: an ISO country code, or "multi" when it serves from several
   * countries (anycast, CDN). Not the registration country of the block.
   */
  location?: string;
}

export interface Report {
  query: string;
  kind: "domain" | "ip";
  generatedAt: string;
  identity?: Identity;
  sections: Section[];
  resolverCheck?: ResolverCheck[];
}

export type Target =
  | { kind: "domain"; name: string }
  | { kind: "ip"; ip: string; version: 4 | 6 };

export function finding(id: string, status: Status, params?: Params): Finding {
  return params ? { id, status, params } : { id, status };
}

export function withSuggest(f: Finding, suggest: Suggestion[]): Finding {
  return suggest.length ? { ...f, suggest } : f;
}
