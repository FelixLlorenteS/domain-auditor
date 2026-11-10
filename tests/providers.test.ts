import { describe, expect, it } from "vitest";
import { dnsProvider } from "../src/core/providers";

describe("dnsProvider", () => {
  it.each([
    [["evan.ns.cloudflare.com", "rachel.ns.cloudflare.com"], "Cloudflare"],
    [["ns3.cloudflare.com", "ns4.cloudflare.com"], "Cloudflare"],
    [["ns-1234.awsdns-12.org"], "Amazon Route 53"],
    [["ns1-01.azure-dns.com"], "Azure DNS"],
    [["ns-cloud-a1.googledomains.com"], "Google Cloud DNS"],
    [["dns104.ovh.net"], "OVHcloud"],
    [["ns1045.ui-dns.com"], "IONOS"],
    [["ns23.domaincontrol.com"], "GoDaddy"],
    [["ns1.dns-parking.com"], "Hostinger"],
    [["hydrogen.ns.hetzner.com"], "Hetzner"],
    [["ns1.vercel-dns.com"], "Vercel"],
  ])("recognises %s as %s", (ns, name) => {
    expect(dnsProvider(ns)).toBe(name);
  });

  it("does not guess for names it cannot tell apart", () => {
    // Google's own infrastructure is not the Google Cloud DNS product.
    expect(dnsProvider(["ns1.google.com", "ns2.google.com"])).toBeUndefined();
    // Arsys serves from IONOS's ui-dns; naming it IONOS would be wrong.
    expect(dnsProvider(["ns-arsys.ui-dns.com"])).toBeUndefined();
    expect(dnsProvider(["ns1.example.net"])).toBeUndefined();
  });
});
