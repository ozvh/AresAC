import path from "path";
import { fileURLToPath } from "url";
import tailwindcss from "@tailwindcss/vite";
import react from "@vitejs/plugin-react";
import { defineConfig, type Plugin } from "vite";
import { SECURITY_HEADERS } from "./server/http-kit.ts";

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

// Arbiter origin. The console is a same-origin observer in production; in dev the
// Vite server proxies /v1 to the local arbiter process.
const ARBITER = process.env["ARES_ARBITER_ORIGIN"] ?? "http://127.0.0.1:8787";

const publicOnly: Plugin = {
  name: "ares-public-only",
  transformIndexHtml: {
    order: "pre",
    handler: (html) => html.replace("/src/main.tsx", "/src/public-main.tsx")
      .replace("Conviction-grade detection without the false positives.", "Private development concept preview; not yet available for purchase."),
  },
  generateBundle(_options, bundle) {
    for (const output of Object.values(bundle)) {
      if (output.type !== "chunk") continue;
      for (const id of Object.keys(output.modules)) {
        const normalized = id.replaceAll("\\", "/");
        if (/\/server\//.test(normalized) || /\/src\/(?:main\.tsx|App\.tsx|components\/|lib\/(?:account|store)\.ts)/.test(normalized)
          || /\/src\/pages\/(?!Landing\.tsx)/.test(normalized)) {
          this.error(`Private module entered public build: ${normalized}`);
        }
      }
      if (/\/(?:v1|admin|account|console|login|signup|request)(?:\/|["'])/.test(output.code)) {
        this.error("Private destination entered public JavaScript");
      }
    }
    // No SPA fallback: typing a private URL must never serve an application route.
    this.emitFile({ type: "asset", fileName: "_headers", source:
      "/*\n" + Object.entries(SECURITY_HEADERS).map(([name, value]) => `  ${name}: ${value}`).join("\n") + "\n",
    });
    // Cloudflare Pages uses this to return 404s instead of its default SPA fallback.
    this.emitFile({ type: "asset", fileName: "404.html", source:
      '<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Page unavailable — Ares Anti Cheat</title></head><body><h1>This page is unavailable</h1><p>Ares is in private development. Accounts and operational features are not publicly available.</p><a href="/">Return to the public preview</a></body></html>',
    });
  },
};

export default defineConfig(({ mode }) => {
  const publicSite = mode === "public" || process.env["CF_PAGES"] === "1";
  return {
  define: { "import.meta.env.VITE_PUBLIC_SITE": JSON.stringify(publicSite) },
  // NOTE: single-file inlining is deliberately NOT used.
  //
  // It would embed the bundle as an inline <script>, which the arbiter's
  // Content-Security-Policy (script-src 'self') blocks outright — a blank console in
  // production. The only way to keep an inlined bundle working would be to add
  // 'unsafe-inline' to script-src, weakening the exact directive that defends this
  // console against injected script. External, content-hashed assets satisfy 'self',
  // stay cacheable, and keep the policy strict.
  plugins: [react(), tailwindcss(), ...(publicSite ? [publicOnly] : [])],
  resolve: {
    alias: {
      "@": path.resolve(__dirname, "src"),
      "@shared": path.resolve(__dirname, "shared"),
    },
  },
  server: {
    host: "127.0.0.1",
    port: 5173,
    strictPort: false,
    proxy: publicSite ? {} : {
      "/v1": { target: ARBITER, changeOrigin: false, ws: false },
    },
  },
  build: {
    outDir: mode === "public" ? "dist-public" : "dist",
    target: "es2022",
    cssMinify: "lightningcss",
    sourcemap: false,
    reportCompressedSize: false,
    assetsDir: "assets",
  },
  };
});
