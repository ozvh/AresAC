/** Send one synthetic exception through the same SDK options and privacy filter as the browser. */
import * as Sentry from "@sentry/react";
import { sentryOptions } from "../shared/sentry.ts";

let status = 0;
Sentry.init({
  ...sentryOptions("development"),
  transport: (options) => Sentry.makeFetchTransport(options, async (input, init) => {
    const response = await fetch(input, { ...init, signal: AbortSignal.timeout(10_000) });
    status = response.status;
    return response;
  }),
});
const eventId = Sentry.captureException(new Error("Ares synthetic connection test — no user data"));
const flushed = await Sentry.flush(15_000);
await Sentry.close();
if (!flushed || status < 200 || status >= 300) {
  console.error(`Sentry connection test failed: HTTP ${status || "no response"}, flushed=${flushed}`);
  process.exitCode = 1;
} else {
  console.log(`Sentry accepted the synthetic test: HTTP ${status}, event ${eventId}`);
}
