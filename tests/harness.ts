/**
 * Shared test harness.
 *
 * Tests need a `Runtime`, and a `Runtime` now owns an account surface, a subscription
 * service and an upload service. Building that by hand in each suite is how a test ends up
 * verifying an assembly nobody deploys, so the assembly lives here and every suite uses
 * it.
 *
 * Three properties are non-negotiable in this file, and each one exists because the
 * alternative silently damages the suite:
 *
 *  - THE DATABASE IS IN MEMORY. A test run must not leave a `ares.db` behind, and a suite
 *    whose state persists between runs is a suite that passes for the wrong reason.
 *  - THE RELAY IS UNREACHABLE AND UNC[REDENTIALED]. No test may emit mail to a real
 *    address, so a request that reaches the relay lands in the spool instead. Where a test
 *    needs a working relay it starts its own recording server and points at that.
 *  - UPLOAD STORAGE IS PER-CALLER. `uploadRoot` defaults to a directory under the system
 *    temporary directory, so a suite that writes a file cannot collide with another.
 */
import { randomBytes } from "node:crypto";
import os from "node:os";
import path from "node:path";
import type { AgentRegistry } from "../server/agents.ts";
import { Auth } from "../server/auth.ts";
import { Store } from "../server/db.ts";
import type { Fleet } from "../server/fleet.ts";
import type { Ledger } from "../server/ledger.ts";
import type { Arbiter } from "../server/machine.ts";
import { Mailer } from "../server/mailer.ts";
import { RequestIntake } from "../server/requests.ts";
import { Runtime } from "../server/runtime.ts";
import type { Broadcaster } from "../server/sse.ts";
import { Subscriptions } from "../server/subscriptions.ts";
import { UploadService, UploadStore } from "../server/uploads.ts";

export type TestRuntimeParts = {
  readonly arbiter: Arbiter;
  readonly ledger: Ledger;
  readonly bus: Broadcaster;
  readonly registry: AgentRegistry;
  readonly fleet: Fleet;
  readonly operatorToken: string;
  /** Fixed clock, for tests that must not depend on how long they take. */
  readonly now?: () => number;
  readonly uploadRoot?: string;
  readonly retentionDays?: number;
  readonly noticeDays?: number;
  readonly sessionKey?: Buffer;
  readonly relay?: { readonly apiKey: string; readonly endpoint: string; readonly recipient?: string };
  readonly spoolPath?: string;
};

export type TestSystem = {
  readonly runtime: Runtime;
  readonly store: Store;
  readonly auth: Auth;
  readonly mailer: Mailer;
};

export function testSystem(parts: TestRuntimeParts): TestSystem {
  const now = parts.now ?? ((): number => Date.now());
  const store = new Store({ file: ":memory:", now });
  const mailer = new Mailer({
    apiKey: parts.relay?.apiKey ?? "",
    from: "ARES Arbiter <onboarding@resend.dev>",
    recipient: parts.relay?.recipient ?? "cagelove094@gmail.com",
    endpoint: parts.relay?.endpoint ?? "http://127.0.0.1:1/emails",
    spoolPath: parts.spoolPath ?? path.join(os.tmpdir(), `ares-test-${randomBytes(6).toString("hex")}.log`),
    timeoutMs: 150,
  });
  const auth = new Auth({
    store,
    sessionKey: parts.sessionKey ?? Buffer.alloc(32, 9),
    cookieSecure: false,
    now,
  });
  const runtime = new Runtime({
    arbiter: parts.arbiter,
    ledger: parts.ledger,
    bus: parts.bus,
    registry: parts.registry,
    fleet: parts.fleet,
    requests: new RequestIntake({ mailer, ledger: parts.ledger }),
    auth,
    store,
    subs: new Subscriptions({ store, mailer, now, noticeDays: parts.noticeDays ?? 14 }),
    uploads: new UploadService({
      store,
      files: new UploadStore(parts.uploadRoot ?? path.join(os.tmpdir(), `ares-uploads-${randomBytes(6).toString("hex")}`)),
      now,
      retentionDays: parts.retentionDays ?? 30,
    }),
    operatorToken: parts.operatorToken,
  });
  return { runtime, store, auth, mailer };
}

/** Convenience for suites that only need the runtime. */
export function testRuntime(parts: TestRuntimeParts): Runtime {
  return testSystem(parts).runtime;
}
