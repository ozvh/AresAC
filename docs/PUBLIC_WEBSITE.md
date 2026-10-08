# Public preview for Cloudflare Pages

Run `npm run build:public`. The deployable folder is `dist-public/`: index.html,
404.html, _headers, assets/, fonts/ and images/. The ZIP is ares-public-site.zip;
index.html is at its root, not inside a dist-public subdirectory.

For automatic GitHub deployments, create a Cloudflare Pages project connected to
ozvh/AresAC, branch main. Set build command `npm run build:public`, output directory
`dist-public`, and NODE_VERSION=24. Leave root directory at the repository root.
Existing Pages settings of `npm run build` / `dist` also work: Cloudflare injects
CF_PAGES=1, which automatically selects the same public-only entry point and guards.
See https://developers.cloudflare.com/pages/configuration/build-configuration/.
Do not add any arbiter keys, passwords or tokens to Cloudflare's build environment.

For a manual upload, choose Workers & Pages, create a Pages project, and use Direct
Upload with ares-public-site.zip (or dist-public/). Upload only these assets.
Direct Upload and Git integration are separate project types; pick Git integration
if you want future pushes deployed automatically. The free pages.dev URL uses HTTPS.

Keep _headers, which sets the same strict security headers as the local server,
including the exact Sentry collector in connect-src. Keep 404.html, which prevents
Cloudflare's default SPA fallback for unknown/private URLs. This preview has no SPA route
fallback, PHP, forms, accounts, upload endpoints or API server. The build fails if
private page, console, server or account-client modules enter its JavaScript graph,
or private destinations survive in the emitted JavaScript. No source maps are emitted.

The public entry point imports only the landing page and privacy-restricted Sentry
monitoring. Concept demonstrations are illustrative; calls to sign up, request a
build or open the console are replaced with architecture links or development status.
Sentry remains the only intentional external application telemetry. To build without
it, set VITE_SENTRY_ENABLED=false in the build environment before build:public.

Never upload the repository, node_modules, server/, .env files, databases, private
keys, logs or uploads. The GitHub repository is public; this build separation does
not make already-published source code private or hide secrets previously published.

Outside Cloudflare (without CF_PAGES=1), `npm run build` still builds the full local application in dist/. Use dev:all for
local backend testing. Sentry now initializes only in public-preview builds, so Vite
development and full local builds do not send local errors. The explicit sentry:test command still sends
one synthetic test only when you run it.

The archive is an upload artifact, not a deployment. Check the live response headers,
404 behavior and landing page after publishing. Do not copy a full
application dist build over this public preview.
