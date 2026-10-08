import assert from "node:assert/strict";
import { test } from "node:test";
import * as Sentry from "@sentry/react";
import { privateErrorEvent, sentryOptions, SENTRY_ORIGIN } from "../shared/sentry.ts";
import { SECURITY_HEADERS } from "../server/http-kit.ts";

test("Sentry strips sensitive context and error text while retaining asset stack locations", () => {
  const result = privateErrorEvent({
    type: undefined,
    event_id: "e".repeat(32), environment: "development",
    user: { email: "private@example.com" }, request: { url: "https://example.com/?token=secret", data: "password" },
    extra: { evidence: "player-secret" }, tags: { player: "player-secret" },
    breadcrumbs: [{ message: "password" }], contexts: { application: { key: "secret" } },
    exception: { values: [{ type: "TypeError", value: "password player-secret", stacktrace: { frames: [
      { filename: "https://private-host/assets/index-abc.js?token=secret#secret", lineno: 12, colno: 7,
        vars: { password: "secret" }, context_line: "player-secret", function: "player-secret" },
      { filename: "https://private-host/player-secret", lineno: 3 },
    ] } }] },
  });
  assert.ok(result);
  const serialized = JSON.stringify(result);
  for (const sensitive of ["private@example.com", "private-host", "player-secret", "password", "token=secret"])
    assert.equal(serialized.includes(sensitive), false);
  assert.deepEqual(result.exception?.values?.[0]?.stacktrace?.frames?.[0], { filename: "index-abc.js", lineno: 12, colno: 7 });
  assert.equal(result.environment, "development");
  assert.equal(privateErrorEvent({ type: undefined, message: "arbitrary payload" }), null);
  assert.equal(sentryOptions("production").dataCollection?.httpBodies?.length, 0);
  assert.equal(sentryOptions("production").dataCollection?.cookies, false);
});

test("SDK transport receives a sanitized exception envelope", async () => {
  let received = "";
  Sentry.init({ ...sentryOptions("development"), transport: () => ({
    send: async (envelope) => { received += JSON.stringify(envelope); return { statusCode: 200 }; },
    flush: async () => true,
  }) });
  try {
    Sentry.captureException(new Error("private-password"), { extra: { playerId: "private-player" } });
    assert.equal(await Sentry.flush(2000), true);
    assert.ok(received.includes("Ares browser error (message redacted)"));
    assert.equal(received.includes("private-password"), false);
    assert.equal(received.includes("private-player"), false);
  } finally {
    await Sentry.close();
  }
});

test("CSP permits only the configured Sentry collector alongside same-origin connections", () => {
  const csp = SECURITY_HEADERS["Content-Security-Policy"] ?? "";
  assert.equal(csp.split(";").find((directive) => directive.trim().startsWith("connect-src"))?.trim(), `connect-src 'self' ${SENTRY_ORIGIN}`);
  assert.ok(csp.includes("script-src 'self';"));
  assert.equal(csp.includes("*.sentry.io"), false);
});
