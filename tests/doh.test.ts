import { describe, expect, it, vi } from "vitest";
import { createResolver, decodeTxt, lookupFailed } from "../src/core/doh";

describe("decodeTxt", () => {
  it("joins quoted character-strings", () => {
    expect(decodeTxt('"v=spf1 include:a.example" " -all"')).toBe("v=spf1 include:a.example -all");
    expect(decodeTxt('"say \\"hi\\"\\059"')).toBe('say "hi";');
    expect(decodeTxt("v=DMARC1; p=reject")).toBe("v=DMARC1; p=reject");
  });
});

describe("createResolver", () => {
  const json = (body: unknown) => new Response(JSON.stringify(body), { status: 200 });

  it("normalises records and caches queries", async () => {
    const fetch = vi.fn(async () =>
      json({ Status: 0, AD: true, Answer: [{ name: "example.com.", type: 15, TTL: 60, data: "10 MX.Example.com." }] }),
    );
    const resolve = createResolver({ fetch });
    const a = await resolve("example.com", "MX");
    await resolve("EXAMPLE.com", "MX");
    expect(fetch).toHaveBeenCalledTimes(1);
    expect(a).toEqual({ status: 0, ad: true, provider: "cloudflare", answers: [{ name: "example.com", type: "MX", ttl: 60, data: "10 mx.example.com" }] });
  });

  it("falls back to the second provider", async () => {
    const fetch = vi.fn(async (url: string | URL | Request) =>
      String(url).includes("cloudflare") ? new Response("", { status: 502 }) : json({ Status: 3 }),
    );
    const answer = await createResolver({ fetch })("nope.example", "A");
    expect(answer.provider).toBe("google");
    expect(answer.status).toBe(3);
  });

  it("asks the second provider when the first one answers SERVFAIL", async () => {
    const fetch = vi.fn(async (url: string | URL | Request) =>
      String(url).includes("cloudflare") ? json({ Status: 2 }) : json({ Status: 0, Answer: [{ name: "example.com.", type: 16, TTL: 60, data: "v=spf1 -all" }] }),
    );
    const answer = await createResolver({ fetch })("example.com", "TXT");
    expect(answer).toMatchObject({ provider: "google", status: 0 });
  });

  it("returns the SERVFAIL when no provider gets an answer", async () => {
    const fetch = vi.fn(async () => json({ Status: 2 }));
    const answer = await createResolver({ fetch })("broken.example", "TXT");
    expect(lookupFailed(answer)).toBe(true);
    expect(fetch).toHaveBeenCalledTimes(2);
  });

  it("throws when every provider fails", async () => {
    const fetch = vi.fn(async () => {
      throw new TypeError("offline");
    });
    await expect(createResolver({ fetch })("example.com", "A")).rejects.toThrow(/DNS query failed/);
  });
});
