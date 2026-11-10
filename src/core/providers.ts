/**
 * DNS hosting providers recognised by their name-server names. Only patterns
 * checked against real NS records (2026-09) are listed: a wrong guess would
 * send the user to the wrong panel, so unknown names get no provider at all.
 */
const DNS_PROVIDERS: Array<[RegExp, string]> = [
  [/\.ns\.cloudflare\.com$/, "Cloudflare"],
  // Cloudflare's own zones (cloudflare.com) use nsN.cloudflare.com.
  [/^ns\d+\.cloudflare\.com$/, "Cloudflare"],
  [/\.awsdns-\d+\.(com|net|org|co\.uk)$/, "Amazon Route 53"],
  [/\.azure-dns\.(com|net|org|info)$/, "Azure DNS"],
  [/^ns-cloud-[a-z]\d\.googledomains\.com$/, "Google Cloud DNS"],
  [/\.ovh\.net$/, "OVHcloud"],
  // Arsys also serves from ui-dns (ns-arsys.*): leave it unnamed rather than mislabel it.
  [/^(?!ns-arsys\.)[^.]+\.ui-dns\.(com|de|org|biz|es)$/, "IONOS"],
  [/\.domaincontrol\.com$/, "GoDaddy"],
  [/\.dondominio\.com$/, "DonDominio"],
  [/\.dns-parking\.com$|^dns\d\.hostinger\.com$/, "Hostinger"],
  [/\.digitalocean\.com$/, "DigitalOcean"],
  [/\.ns\.hetzner\.(com|de)$|\.your-server\.de$|\.second-ns\.(com|de)$/, "Hetzner"],
  [/\.vercel-dns\.com$/, "Vercel"],
  [/\.nsone\.net$/, "NS1"],
];

export function dnsProvider(nsHosts: string[]): string | undefined {
  return DNS_PROVIDERS.find(([re]) => nsHosts.some((h) => re.test(h)))?.[1];
}
