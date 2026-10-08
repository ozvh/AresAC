import * as Sentry from "@sentry/react";
import { sentryOptions } from "../shared/sentry.ts";
import { PUBLIC_SITE } from "./landing/public-mode";

// Only the public preview reports errors. Full/private builds and Vite development stay local.
if (import.meta.env.PROD && PUBLIC_SITE && import.meta.env["VITE_SENTRY_ENABLED"] !== "false") {
  Sentry.init({
    ...sentryOptions(import.meta.env.PROD ? "production" : "development"),
    integrations: [Sentry.globalHandlersIntegration({ onerror: true, onunhandledrejection: true })],
  });
}
