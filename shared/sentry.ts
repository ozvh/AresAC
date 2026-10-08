import type { BrowserOptions, ErrorEvent } from "@sentry/react";

/** Public browser ingestion address supplied by the project's owner; not an auth token. */
export const SENTRY_DSN = "https://abdf1049ce45a51850b14387ac6d865d@o4512220601647104.ingest.us.sentry.io/4512220623929344";
export const SENTRY_ORIGIN = new URL(SENTRY_DSN).origin;

/** Build a fresh diagnostic envelope so arbitrary application context cannot escape. */
export function privateErrorEvent(event: ErrorEvent): ErrorEvent | null {
  if (!event.exception?.values?.length) return null;
  return {
    type: undefined,
    ...(event.event_id === undefined ? {} : { event_id: event.event_id }),
    ...(event.timestamp === undefined ? {} : { timestamp: event.timestamp }),
    platform: "javascript",
    level: "error",
    environment: event.environment === "development" ? "development" : "production",
    release: "ares-web@1.0.0",
    exception: {
      values: event.exception.values.map((exception) => ({
        type: ["Error", "TypeError", "ReferenceError", "SyntaxError", "RangeError", "URIError", "EvalError"].includes(exception.type ?? "")
          ? (exception.type ?? "Error") : "Error",
        value: "Ares browser error (message redacted)",
        stacktrace: {
          frames: (exception.stacktrace?.frames ?? []).map((frame) => {
            // Keep only build asset filenames, never hostnames, query strings or fragment data.
            const filename = frame.filename?.split(/[?#]/, 1)[0]?.match(/\/assets\/([A-Za-z0-9_-]+\.js)$/)?.[1];
            return {
              ...(filename === undefined ? {} : { filename }),
              ...(frame.lineno === undefined ? {} : { lineno: frame.lineno }),
              ...(frame.colno === undefined ? {} : { colno: frame.colno }),
            };
          }),
        },
      })),
    },
  };
}

export function sentryOptions(environment: "development" | "production"): BrowserOptions {
  return {
    dsn: SENTRY_DSN,
    environment,
    release: "ares-web@1.0.0",
    // No DOM/network/console breadcrumbs, replay, tracing or automatic session tracking.
    defaultIntegrations: false,
    maxBreadcrumbs: 0,
    sendClientReports: false,
    dataCollection: {
      userInfo: false, cookies: false, httpHeaders: false, httpBodies: [],
      urlQueryParams: false, stackFrameVariables: false, frameContextLines: 0,
      genAI: { inputs: false, outputs: false }, databaseQueryData: false, queues: false,
      graphQL: { document: false, variables: false },
    },
    beforeSend: privateErrorEvent,
  };
}
