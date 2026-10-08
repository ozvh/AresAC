# Ares website error monitoring

The React SDK is pinned in package.json. src/sentry.ts initializes before React
mounts; the root ErrorBoundary captures render failures and offers a reload message.
Only global uncaught errors/rejections are instrumented. No replay, tracing, logging,
metrics, DOM/network breadcrumbs or automatic session integration is installed.

shared/sentry.ts contains the owner's public browser DSN and the collector origin.
The server CSP allows that exact origin alongside same-origin connections. This DSN
is not an administrative auth token. Never put a Sentry auth token in browser code.
If the project changes, update the DSN; the collector origin derives from it.

The dataCollection configuration explicitly disables personal/request data. The
beforeSend filter builds a new envelope containing only event ID/time, environment,
release, known exception types, a generic redacted error message and built-asset
filename/line/column. It removes user data, request bodies/headers/URLs, tags, extras,
contexts, breadcrumbs, variables, function names and source context. SDK-generated
envelope metadata and the collector's network processing are separate from this
application event filter. Original error messages are intentionally unavailable.

Vite development uses the development environment; built assets use production.
Set VITE_SENTRY_ENABLED=false before starting/building Vite to disable initialization.
The switch is public, not a secret; changes require a new frontend build. Never
expose other credentials with the VITE_ prefix.

Run `npm run sentry:test` to explicitly send one harmless synthetic development
exception through the configured SDK/filter. It reports collector HTTP acceptance
and the event ID. In Sentry, select the development environment and find that event;
its message is "Ares browser error (message redacted)". An accepted HTTP response
does not prove dashboard indexing. This test checks ingestion, not browser CSP;
the CSP and SDK envelope have their own regression tests.

No source-map upload or Sentry auth token is configured. Stack locations currently
refer to bundled assets. Source maps can later be uploaded privately during CI without
serving them publicly. Update the release label with each application release.

This setup monitors the React website only. Node server and Unity monitoring need
separate project configurations and integrations. It does not send cheat evidence.
