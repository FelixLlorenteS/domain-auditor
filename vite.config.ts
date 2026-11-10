import { resolve } from "node:path";
import type { Plugin } from "vite";
import { defineConfig } from "vitest/config";

/**
 * Content Security Policy of both pages. It goes in a <meta> tag, which works on
 * any host and in the desktop app, and again as a real HTTP header through
 * Cloudflare Pages' `_headers` file, which a <meta> cannot replace: only a header
 * can forbid framing (frame-ancestors). Only in production builds: the dev server
 * injects inline styles.
 */
const CSP = [
  "default-src 'self'",
  "connect-src https:",
  "img-src 'self' data:",
  "style-src 'self'",
  "font-src 'self'",
  "script-src 'self'",
  "base-uri 'none'",
  "form-action 'none'",
].join("; ");

/**
 * Security headers for Cloudflare Pages (`dist/_headers`). The site audits other
 * domains' headers, so its own pass its checks: HSTS for a year (RFC 6797), no
 * framing (RFC 7034 and CSP frame-ancestors), nosniff, no referrer and no access
 * to the camera, microphone or location. Hashed assets are cached for good.
 */
export const HEADERS = `/*
  Content-Security-Policy: ${CSP}; frame-ancestors 'none'
  Strict-Transport-Security: max-age=31536000; includeSubDomains
  X-Frame-Options: DENY
  X-Content-Type-Options: nosniff
  Referrer-Policy: no-referrer
  Permissions-Policy: camera=(), microphone=(), geolocation=(), payment=(), usb=()
  Cross-Origin-Opener-Policy: same-origin

/assets/*
  Cache-Control: public, max-age=31536000, immutable
`;

function csp(): Plugin {
  return {
    name: "csp",
    apply: "build",
    transformIndexHtml: () => [{ tag: "meta", attrs: { "http-equiv": "Content-Security-Policy", content: CSP }, injectTo: "head-prepend" }],
    generateBundle() {
      this.emitFile({ type: "asset", fileName: "_headers", source: HEADERS });
    },
  };
}

export default defineConfig({
  base: "/",
  plugins: [csp()],
  // Never inline assets as data: URIs, so the CSP can stay at font-src 'self'.
  build: {
    target: "es2022",
    sourcemap: false,
    assetsInlineLimit: 0,
    rollupOptions: {
      input: { main: resolve(import.meta.dirname, "index.html"), wiki: resolve(import.meta.dirname, "wiki/index.html") },
    },
  },
  test: { environment: "node", include: ["tests/**/*.test.ts"] },
});
