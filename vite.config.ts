import path from "path";
import { fileURLToPath } from "url";
import tailwindcss from "@tailwindcss/vite";
import react from "@vitejs/plugin-react";
import { defineConfig } from "vite";

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

// Arbiter origin. The console is a same-origin observer in production; in dev the
// Vite server proxies /v1 to the local arbiter process.
const ARBITER = process.env["ARES_ARBITER_ORIGIN"] ?? "http://127.0.0.1:8787";

export default defineConfig({
  // NOTE: single-file inlining is deliberately NOT used.
  //
  // It would embed the bundle as an inline <script>, which the arbiter's
  // Content-Security-Policy (script-src 'self') blocks outright — a blank console in
  // production. The only way to keep an inlined bundle working would be to add
  // 'unsafe-inline' to script-src, weakening the exact directive that defends this
  // console against injected script. External, content-hashed assets satisfy 'self',
  // stay cacheable, and keep the policy strict.
  plugins: [react(), tailwindcss()],
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
    proxy: {
      "/v1": { target: ARBITER, changeOrigin: false, ws: false },
    },
  },
  build: {
    target: "es2022",
    cssMinify: "lightningcss",
    sourcemap: false,
    reportCompressedSize: false,
    assetsDir: "assets",
  },
});
