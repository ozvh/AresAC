import * as Sentry from "@sentry/react";
import { sentryOptions } from "../shared/sentry.ts";

// Only uncaught errors/rejections are instrumented. Application payloads stay local.
if (import.meta.env["VITE_SENTRY_ENABLED"] !== "false") {
  Sentry.init({
    ...sentryOptions(import.meta.env.PROD ? "production" : "development"),
    integrations: [Sentry.globalHandlersIntegration({ onerror: true, onunhandledrejection: true })],
  });
}
