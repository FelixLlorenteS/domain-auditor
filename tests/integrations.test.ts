import { describe, expect, it } from "vitest";
import { sendersOf, verificationsOf } from "../src/core/integrations";

describe("integrations", () => {
  it("names documented verification tokens and keeps unknown ones as they are", () => {
    const txt = ["google-site-verification=abc", "MS=ms12345678", "acme-domain-verification=xyz", "v=spf1 -all", "hello world"];
    expect(verificationsOf(txt).map((i) => i.service)).toEqual(["Google (Search Console / Workspace)", "Microsoft 365", "acme"]);
  });

  it("lists the services SPF lets send mail", () => {
    expect(sendersOf("v=spf1 include:_spf.google.com include:mail.example.net ~all").map((i) => i.service)).toEqual(["Google Workspace", "mail.example.net"]);
    expect(sendersOf(undefined)).toEqual([]);
  });
});
