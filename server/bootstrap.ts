/**
 * Composition root.
 *
 * Everything that needs a live system — the bootstrap process, the load harness and the
 * test suite — calls this rather than assembling the same nine objects itself. The reason
 * is the one that matters for security work: a test that builds its own runtime can build
 * a *different* runtime, and then it is verifying a system nobody deploys. There is one
 * assembly, and every caller gets that one.
 *
 * Secrets are resolved here and nowhere else. The session key, the telemetry master key
 * and the operator token are read from the environment, and when one is absent a fresh
 * value is generated for the lifetime of the process. That fallback is deliberately loud
 * in the returned `notices` rather than silent: a deployment that forgot to set
 * `ARES_SESSION_KEY` is not broken, it just logs everyone out on restart, and the operator
 * should be told which of those two things is happening.
 */
import { randomBytes } from "node:crypto";
import { existsSync } from "node:fs";
import { aresEnvironment } from "./legacy-env.ts";
import { AgentRegistry } from "./agents.ts";
import { Auth } from "./auth.ts";
import { retentionDays, renewalNoticeDays, Store } from "./db.ts";
import { Fleet } from "./fleet.ts";
import { Ledger } from "./ledger.ts";
import { Arbiter } from "./machine.ts";
import { Mailer } from "./mailer.ts";
import { RequestIntake } from "./requests.ts";
import { Runtime } from "./runtime.ts";
import { Broadcaster } from "./sse.ts";
import { Subscriptions } from "./subscriptions.ts";
import { UploadService, UploadStore } from "./uploads.ts";
import { LIMITS } from "../shared/protocol.ts";

export type BootstrapOptions = {
  /** SQLite file, or ":memory:" for a process that must leave nothing behind. */
  readonly dbFile?: string;
  readonly uploadDir?: string;
  readonly sessions?: number;
  readonly tps?: number;
  readonly seed?: number;
  readonly port?: number;
  readonly env?: NodeJS.ProcessEnv;
  readonly now?: () => number;
};

export type System = {
  readonly runtime: Runtime;
  readonly registry: AgentRegistry;
  readonly ledger: Ledger;
  readonly store: Store;
  readonly auth: Auth;
  readonly mailer: Mailer;
  readonly uploads: UploadService;
  readonly subs: Subscriptions;
  readonly requests: RequestIntake;
  readonly fleet: Fleet;
  /** Non-fatal configuration findings, for the operator to read at boot. */
  readonly notices: readonly string[];
};

/** Read a hex secret from the environment, or generate one and say so. */
function secret(env: NodeJS.ProcessEnv, name: string, bytes: number, notices: string[]): Buffer {
  const raw = (env[name] ?? "").trim();
  if (/^[0-9a-f]{64}$/.test(raw)) return Buffer.from(raw, "hex");
  if (raw !== "") notices.push(`${name} is set but is not 64 hex characters; a fresh key was generated for this process`);
  else notices.push(`${name} is unset; a fresh key was generated, so this state will not survive a restart`);
  return randomBytes(bytes);
}

export function bootstrap(options: BootstrapOptions = {}): System {
  const env = aresEnvironment(options.env ?? process.env);
  const notices: string[] = [];
  const now = options.now ?? ((): number => Date.now());

  const { master, ephemeral } = AgentRegistry.masterFromEnv(env);
  if (ephemeral) notices.push("ARES_MASTER_KEY is unset; the enrolled agent fleet changes on every boot");

  // The store is opened before the ledger, because the ledger recovers its chain from it:
  // the running head and sequence must come from what is on disk, not from a fresh zero.
  const dbFile = options.dbFile ?? env["ARES_DB"] ?? (existsSync(".zeus-data/zeus.db") ? ".zeus-data/zeus.db" : ".ares-data/ares.db");
  const store = new Store({ file: dbFile, now });

  const registry = new AgentRegistry(master);
  const ledger = new Ledger({ store });
  // A tamper found at boot is something the operator must read, not a detail. The chain
  // stays broken for the life of the process — appending cannot repair it — so this is the
  // one line that names which record stopped verifying.
  if (ledger.recovery !== null && !ledger.recovery.ok) {
    notices.push(
      `the decision ledger failed verification at record ${String(ledger.recovery.at)} (${ledger.recovery.records} read from ${dbFile}); the chain was modified outside this process`,
    );
  }
  const arbiter = new Arbiter(ledger);
  const bus = new Broadcaster(LIMITS.replayRing);
  const fleet = new Fleet(registry, {
    sessions: options.sessions ?? Number(env["ARES_SESSIONS"] ?? 6),
    tps: options.tps ?? Number(env["ARES_TPS"] ?? 0),
    origin: `http://127.0.0.1:${options.port ?? Number(env["PORT"] ?? 8787)}`,
    seed: options.seed ?? Number(env["ARES_SEED"] ?? 0x5eed),
  });

  const auth = new Auth({
    store,
    // Not the master key. A telemetry MAC key and a session key are different authorities,
    // and one derivation serving both means a leak of either is a leak of both.
    sessionKey: secret(env, "ARES_SESSION_KEY", 32, notices),
    cookieSecure: env["ARES_COOKIE_SECURE"] === "1",
    now,
  });

  const mailer = Mailer.fromEnv(env);
  const requests = new RequestIntake({ mailer, ledger });
  const subs = new Subscriptions({ store, mailer, now, noticeDays: renewalNoticeDays(env) });
  const uploads = new UploadService({
    store,
    files: new UploadStore(options.uploadDir ?? env["ARES_UPLOAD_DIR"] ?? (existsSync(".zeus-data/uploads") ? ".zeus-data/uploads" : ".ares-data/uploads")),
    now,
    retentionDays: retentionDays(env),
  });

  const runtime = new Runtime({
    arbiter,
    ledger,
    bus,
    registry,
    fleet,
    requests,
    auth,
    store,
    subs,
    uploads,
    operatorToken: resolveOperatorToken(env, notices),
  });

  return { runtime, registry, ledger, store, auth, mailer, uploads, subs, requests, fleet, notices };
}

function resolveOperatorToken(env: NodeJS.ProcessEnv, notices: string[]): string {
  const raw = env["ARES_OPERATOR_TOKEN"];
  if (typeof raw === "string" && raw.length >= 32) return raw;
  if (typeof raw === "string" && raw !== "") {
    notices.push("ARES_OPERATOR_TOKEN is shorter than 32 characters; a fresh token was generated instead");
  }
  return randomBytes(24).toString("hex");
}
