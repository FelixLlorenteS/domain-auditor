import { describe, expect, it } from "vitest";
import { checkMailExtras, checkMx, mtaStsPolicy, mxProvider, spfAuthorisesSenders } from "../src/core/mail";
import { fakeResolver } from "./helpers";

describe("mail helpers", () => {
  it("detects the provider and its SPF include", () => {
    expect(mxProvider(["aspmx.l.google.com"])).toEqual({ name: "Google (Gmail / Workspace)", spf: "_spf.google.com" });
    expect(mxProvider(["mx.zoho.eu"])?.spf).toBe("zohomail.eu");
    expect(mxProvider(["mx.example.net"])).toBeNull();
  });

  it("recognises providers only by names that are theirs (audit of 2026-09-30)", () => {
    expect(mxProvider(["sidn-nl.v-v1.mx.microsoft"])?.name).toBe("Microsoft 365");
    expect(mxProvider(["smtpin.zoho.in"])?.spf).toBe("zohomail.in");
    expect(mxProvider(["inbound-smtp.eu-west-1.amazonaws.com"])?.spf).toBe("amazonses.com");
    // Any EC2 host ends in amazonaws.com: that does not make it Amazon SES.
    expect(mxProvider(["ec2-192-0-2-1.compute-1.amazonaws.com"])).toBeNull();
    // IONOS outside Spain and Germany: named, but no include proposed without checking it.
    expect(mxProvider(["mx00.ionos.com"])).toEqual({ name: "IONOS" });
    expect(mxProvider(["mx00.ionos.es"])?.spf).toBe("_spf-eu.ionos.com");
  });

  it("knows whether an SPF authorises anyone", () => {
    expect(spfAuthorisesSenders(["v=spf1 -all"])).toBe(false);
    expect(spfAuthorisesSenders(["v=spf1 include:_spf.google.com ~all"])).toBe(true);
    expect(spfAuthorisesSenders([])).toBe(false);
  });

  it("suggests the no-mail records only for domains that do not send mail", () => {
    const quiet = checkMx([], { domain: "example.com", spf: [], hasDmarc: false })[0];
    expect(quiet?.suggest?.map((s) => `${s.type} ${s.name} ${s.value}`)).toEqual([
      "MX example.com 0 .",
      "TXT example.com v=spf1 -all",
      "TXT _dmarc.example.com v=DMARC1; p=reject;",
    ]);
    const sender = checkMx([], { domain: "example.com", spf: ["v=spf1 include:_spf.google.com ~all"], hasDmarc: true })[0];
    expect(sender?.suggest).toBeUndefined();
  });
});

describe("MTA-STS and TLS-RPT suggestions", () => {
  it("builds the policy from the real MX hosts, with CRLF line endings (RFC 8461, section 3.2)", () => {
    expect(mtaStsPolicy(["mx1.example.com", "mx2.example.com"])).toBe(
      "version: STSv1\r\nmode: testing\r\nmx: mx1.example.com\r\nmx: mx2.example.com\r\nmax_age: 86400\r\n",
    );
  });

  it("attaches the policy file and never invents a mailbox", async () => {
    const { findings } = await checkMailExtras("example.com", fakeResolver({}), ["mx1.example.com"]);
    const sts = findings.find((f) => f.id === "mta-sts.missing");
    expect(sts?.files?.[0]?.url).toBe("https://mta-sts.example.com/.well-known/mta-sts.txt");
    expect(sts?.files?.[0]?.content).toContain("mx: mx1.example.com");
    const rpt = findings.find((f) => f.id === "tls-rpt.missing");
    expect(rpt?.suggest?.[0]).toMatchObject({ value: "v=TLSRPTv1; rua=mailto:{mailbox}", input: "mailbox" });
  });
});

describe("published MTA-STS", () => {
  const txt = { "_mta-sts.example.com TXT": ["v=STSv1; id=1769609691387;"] };

  it("warns when the policy host does not exist, as the TXT alone does nothing", async () => {
    const { findings } = await checkMailExtras("example.com", fakeResolver(txt), ["mx1.example.com"]);
    const f = findings.find((x) => x.id.startsWith("mta-sts"));
    expect(f).toMatchObject({ id: "mta-sts.no-host", status: "warn", params: { host: "mta-sts.example.com" } });
    expect(f?.files?.[0]?.content).toContain("mx: mx1.example.com");
  });

  it("does not claim enforcement it cannot see (fastmail.com and yahoo.com were in testing mode)", async () => {
    const r = fakeResolver({ ...txt, "mta-sts.example.com A": ["192.0.2.1"] });
    const f = (await checkMailExtras("example.com", r)).findings.find((x) => x.id.startsWith("mta-sts"));
    expect(f).toMatchObject({ id: "mta-sts.unverified", status: "info" });
  });

  it("does not take a wildcard answer as proof either", async () => {
    const r = fakeResolver({ ...txt, "*.example.com A": ["192.0.2.1"] });
    const f = (await checkMailExtras("example.com", r)).findings.find((x) => x.id.startsWith("mta-sts"));
    expect(f?.status).not.toBe("ok");
  });

  it("ignores a TXT without the `v=STSv1;` start (RFC 8461, section 3.1)", async () => {
    const r = fakeResolver({ "_mta-sts.example.com TXT": ["v=STSv1 id=1"], "mta-sts.example.com A": ["192.0.2.1"] });
    const f = (await checkMailExtras("example.com", r)).findings.find((x) => x.id.startsWith("mta-sts"));
    expect(f?.id).toBe("mta-sts.invalid");
  });

  it("flags a record without a valid id", async () => {
    const r = fakeResolver({ "_mta-sts.example.com TXT": ["v=STSv1;"], "mta-sts.example.com A": ["192.0.2.1"] });
    const f = (await checkMailExtras("example.com", r)).findings.find((x) => x.id.startsWith("mta-sts"));
    expect(f?.id).toBe("mta-sts.invalid");
  });

  it("treats two TLS-RPT records as none (RFC 8460, section 3)", async () => {
    const r = fakeResolver({ "_smtp._tls.example.com TXT": ["v=TLSRPTv1; rua=mailto:a@example.com", "v=TLSRPTv1; rua=mailto:b@example.com"] });
    const ids = (await checkMailExtras("example.com", r)).findings.map((x) => x.id);
    expect(ids).toContain("tls-rpt.invalid");
  });

  it("checks that TLS-RPT has a destination and BIMI a certificate", async () => {
    const r = fakeResolver({
      "_smtp._tls.example.com TXT": ["v=TLSRPTv1;"],
      "default._bimi.example.com TXT": ["v=BIMI1; l=https://example.com/logo.svg"],
    });
    const ids = (await checkMailExtras("example.com", r)).findings.map((x) => x.id);
    expect(ids).toContain("tls-rpt.invalid");
    expect(ids).toContain("bimi.found-no-vmc");
  });
});
