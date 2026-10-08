/**
 * HTTP transport. The only surface in this system that reads from a socket.
 *
 * Posture:
 *  - Bound to loopback by the caller. Nothing here listens on a public interface.
 *  - No CORS headers are ever emitted. A browser origin that is not explicitly
 *    configured is refused, which closes CSRF and cross-site stream theft at once.
 *  - The body ceiling is enforced while counting bytes as they arrive; an oversized
 *    request is refused rather than buffered and then judged.
 *  - Content-Type is required on writes. form-urlencoded and text/plain POSTs are
 *    refused outright, so the classic CSRF request shapes are not even parseable.
 *  - Every response is no-store. Telemetry must never be cached by an intermediary.
 */
import { createReadStream, statSync } from "node:fs";
import { createServer, type IncomingMessage, type ServerResponse } from "node:http";
import { createServer as createHttpsServer } from "node:https";
import type { Server as NetServer } from "node:net";
import path from "node:path";
import {
  LIMITS,
  REQUEST_LIMITS,
  canonicalEvent,
  ROLE_RING,
  SCENARIOS,
  type ControlAction,
  type IngestEvent,
} from "../shared/protocol.ts";
import { verifyMac } from "./agents.ts";
import { rolePermitted } from "./catalog.ts";
import { MAX_SKEW_MS } from "./limiter.ts";
import {
  SECURITY_HEADERS,
  STATUS_OF,
  constantTimeEqual,
  fail,
  header,
  json,
  originAllowed,
  readBody,
  send,
  sourceOf,
} from "./http-kit.ts";
import { handleAccountRoutes, ownsAccountPath } from "./routes-auth.ts";
import type { Runtime } from "./runtime.ts";
import { parseIngest } from "./validate.ts";

export type TransportConfig = {
  readonly runtime: Runtime;
  /** Origins permitted to call this API from a browser context. */
  readonly consoleOrigins: readonly string[];
  /** Directory of built console assets, or null to serve the API only. */
  readonly staticDir: string | null;
  /**
   * PEM material. When present the listener speaks TLS; when absent it does not.
   *
   * The material is passed in rather than read here: where a certificate comes from is a
   * deployment decision (a file, a secret mount, an in-memory value in a test), and this
   * module should not be the thing that knows about paths on disk.
   */
  readonly tls?: { readonly cert: Buffer; readonly key: Buffer };
};

const CONTENT_TYPES: Readonly<Record<string, string>> = {
  ".html": "text/html; charset=utf-8",
  ".js": "text/javascript; charset=utf-8",
  ".mjs": "text/javascript; charset=utf-8",
  ".css": "text/css; charset=utf-8",
  ".json": "application/json; charset=utf-8",
  ".svg": "image/svg+xml",
  ".ico": "image/x-icon",
  ".png": "image/png",
  ".jpg": "image/jpeg",
  ".jpeg": "image/jpeg",
  ".webp": "image/webp",
  ".woff2": "font/woff2",
  ".txt": "text/plain; charset=utf-8",
};

const HEX12 = /^[0-9a-f]{12}$/;

function parseControl(raw: string): ControlAction | null {
  let parsed: unknown;
  try {
    parsed = JSON.parse(raw);
  } catch {
    return null;
  }
  if (typeof parsed !== "object" || parsed === null) return null;
  const r = parsed as Record<string, unknown>;
  const op = r["op"];
  if (op === "PAUSE") return { op: "PAUSE" };
  if (op === "RESUME") return { op: "RESUME" };
  if (op === "RATE") {
    const tps = r["tps"];
    if (typeof tps !== "number" || !Number.isFinite(tps) || tps < 0 || tps > 200_000) return null;
    return { op: "RATE", tps: Math.floor(tps) };
  }
  if (op === "SCENARIO") {
    const name = r["name"];
    if (typeof name !== "string") return null;
    const known = SCENARIOS.find((candidate) => candidate === name);
    if (known === undefined) return null;
    return { op: "SCENARIO", name: known };
  }
  if (op === "RELEASE" || op === "FLAG") {
    const su = r["su"];
    if (typeof su !== "string" || !HEX12.test(su)) return null;
    return op === "RELEASE" ? { op: "RELEASE", su } : { op: "FLAG", su };
  }
  return null;
}

export function createArbiterServer(config: TransportConfig): NetServer {
  const listener = (req: IncomingMessage, res: ServerResponse): void => {
    handle(req, res, config).catch(() => {
      if (!res.writableEnded) fail(res, 500, "MALFORMED", "handler failure");
    });
  };
  // The return type is `net.Server` because both listeners are sockets: every caller uses
  // listen, close and error handling, and none of them reaches for an HTTP-specific
  // method. Typing it as one of the two concrete servers would be a claim the other one
  // does not satisfy.
  return config.tls === undefined
    ? createServer(listener)
    : createHttpsServer({ cert: config.tls.cert, key: config.tls.key }, listener);
}

async function handle(req: IncomingMessage, res: ServerResponse, config: TransportConfig): Promise<void> {
  const { runtime } = config;
  const url = new URL(req.url ?? "/", "http://127.0.0.1");
  const pathname = url.pathname;
  const method = req.method ?? "GET";

  /* ---------------- ingest ---------------- */

  if (pathname === "/v1/ingest") {
    if (method !== "POST") return fail(res, 405, "BAD_METHOD", "POST required");
    if (!originAllowed(req, config.consoleOrigins)) return fail(res, 403, "FORBIDDEN", "origin refused");

    const ctype = header(req, "content-type");
    if (ctype === null || !ctype.toLowerCase().startsWith("application/json")) {
      return fail(res, 415, "BAD_CT", "application/json required");
    }
    const declared = Number(header(req, "content-length") ?? "0");
    if (Number.isFinite(declared) && declared > LIMITS.bodyBytes) {
      return fail(res, 413, "TOO_LARGE", "declared body exceeds ceiling");
    }

    const read = await readBody(req, LIMITS.bodyBytes);
    if (!read.ok) {
      runtime.arbiter.countRejected("rej");
      if (read.reason === "ABORTED") {
        return fail(res, 400, "MALFORMED", "request aborted before the body completed");
      }
      // Reply first, then tear the socket down: destroying it before the response
      // flushes would surface to the sender as a network error rather than a verdict.
      res.on("finish", () => req.destroy());
      return fail(res, 413, "TOO_LARGE", "body ceiling breached");
    }

    const parsed = parseIngest(read.body);
    if (!parsed.ok) {
      runtime.arbiter.countRejected("rej");
      return fail(res, 400, parsed.code, parsed.msg);
    }

    const events = parsed.events;
    const first = events[0];
    if (first === undefined) return fail(res, 400, "SCHEMA", "empty batch");

    // One batch, one principal. A batch spanning agents cannot be covered by a
    // single MAC, so it is refused rather than partially trusted.
    for (const event of events) {
      if (event.a !== first.a) return fail(res, 400, "SCHEMA", "batch spans multiple agents");
    }

    const agent = runtime.registry.get(first.a);
    const sig = header(req, "x-ares-sig");
    if (agent === undefined || sig === null) {
      runtime.arbiter.countRejected("sig");
      return fail(res, 401, "SIG", "unauthenticated generator");
    }
    const canonical = events.map((e) => canonicalEvent(e)).join("\n");
    if (!verifyMac(agent.key, canonical, sig)) {
      runtime.arbiter.countRejected("sig");
      return fail(res, 401, "SIG", "signature mismatch");
    }

    const now = Date.now();

    // Velocity gate: the batch is charged for every sample it carries, so a larger
    // batch buys no extra budget.
    if (!runtime.limiter.take(agent.id, now, LIMITS.ratePerSec, LIMITS.rateBurst, events.length)) {
      runtime.arbiter.countRejected("rl");
      res.setHeader("Retry-After", "1");
      return fail(res, 429, "RATE", "input velocity exceeded");
    }

    const ordered: IngestEvent[] = [];
    for (const event of events) {
      if (Math.abs(now - event.t) > MAX_SKEW_MS) {
        runtime.arbiter.countRejected("rej");
        return fail(res, 400, "STALE", "sender clock outside skew window");
      }
      if (runtime.limiter.admitSequence(agent.id, event.s, now) !== "OK") {
        runtime.arbiter.countRejected("rpy");
        return fail(res, 409, "REPLAY", "sequence not monotonic");
      }
      if (event.r !== ROLE_RING[agent.role]) {
        runtime.arbiter.countRejected("spf");
        return fail(res, 403, "ROLE", "declared ring contradicts provisioned role");
      }
      if (!rolePermitted(event.c, agent.role)) {
        runtime.arbiter.countRejected("spf");
        return fail(res, 403, "ROLE", "evidence code not authorised for this ring");
      }
      ordered.push(event);
    }

    const started = performance.now();
    const tag = agent.id.slice(0, 8);
    let admitted = 0;
    for (const event of ordered) {
      if (runtime.paused) {
        runtime.arbiter.countRejected("drop");
        continue;
      }
      const result = runtime.arbiter.adjudicate(
        {
          subjectDigest: event.k,
          role: agent.role,
          code: event.c,
          measurement: event.m,
          sourceClock: event.t,
          agentTag: tag,
        },
        Date.now(),
      );
      runtime.arbiter.countAccepted();
      runtime.emit(result.event);
      if (event.c === "XD") runtime.bumpCorpus(1);
      admitted += 1;
    }
    const elapsed = performance.now() - started;
    runtime.latency.push(admitted === 0 ? elapsed : elapsed / admitted);

    return json(res, 202, { ok: true, n: admitted });
  }

  /* ---------------- read surfaces ---------------- */

  if (pathname === "/v1/stream") {
    if (method !== "GET") return fail(res, 405, "BAD_METHOD", "GET required");
    if (!originAllowed(req, config.consoleOrigins)) return fail(res, 403, "FORBIDDEN", "origin refused");
    const lastIdRaw = header(req, "last-event-id");
    const lastId = lastIdRaw !== null && /^\d+$/.test(lastIdRaw) ? Number(lastIdRaw) : null;
    const attached = runtime.bus.subscribe(res, lastId);
    if (!attached.ok) return fail(res, 503, "RATE", attached.reason);
    return;
  }

  if (pathname === "/v1/snapshot") {
    if (method !== "GET") return fail(res, 405, "BAD_METHOD", "GET required");
    if (!originAllowed(req, config.consoleOrigins)) return fail(res, 403, "FORBIDDEN", "origin refused");
    return json(res, 200, runtime.snapshot());
  }

  if (pathname === "/v1/health") {
    if (method !== "GET") return fail(res, 405, "BAD_METHOD", "GET required");
    const stats = runtime.arbiter.stats();
    const fleet = runtime.fleet.stats();
    return json(res, 200, {
      ok: true,
      uptimeMs: Date.now() - runtime.bootedAt,
      subscribers: runtime.bus.subscribers,
      frames: runtime.bus.published,
      droppedFrames: runtime.bus.dropped,
      paused: runtime.paused,
      scenario: runtime.fleet.scenarioName,
      emitted: fleet.emitted,
      fleetFailures: fleet.failed,
      accepted: stats.rx,
      chainOk: runtime.ledger.verify().ok,
      requests: runtime.requests.stats(),
    });
  }

  if (pathname.startsWith("/v1/subject/")) {
    if (method !== "GET") return fail(res, 405, "BAD_METHOD", "GET required");
    if (!originAllowed(req, config.consoleOrigins)) return fail(res, 403, "FORBIDDEN", "origin refused");
    const tag = pathname.slice("/v1/subject/".length);
    if (!HEX12.test(tag)) return fail(res, 400, "SCHEMA", "subject tag must be 12 hex chars");
    const detail = runtime.arbiter.detail(tag, Date.now());
    if (detail === null) return fail(res, 404, "NOT_FOUND", "subject not tracked");
    return json(res, 200, detail);
  }

  /* ---------------- control ---------------- */

  if (pathname === "/v1/control") {
    if (method !== "POST") return fail(res, 405, "BAD_METHOD", "POST required");
    if (!originAllowed(req, config.consoleOrigins)) return fail(res, 403, "FORBIDDEN", "origin refused");

    const presented = header(req, "x-ares-op") ?? "";
    if (!constantTimeEqual(presented, runtime.operatorToken)) {
      return fail(res, 403, "FORBIDDEN", "operator token required");
    }
    const ctype = header(req, "content-type");
    if (ctype === null || !ctype.toLowerCase().startsWith("application/json")) {
      return fail(res, 415, "BAD_CT", "application/json required");
    }
    // A control action is a mutation: it may not be issued faster than an operator
    // could plausibly read the result of the previous one.
    if (!runtime.limiter.take("__operator__", Date.now(), 1000 / LIMITS.controlMinIntervalMs, 1, 1)) {
      return fail(res, 429, "RATE", "control plane throttled");
    }

    const read = await readBody(req, 2048);
    if (!read.ok) {
      if (read.reason === "ABORTED") return fail(res, 400, "MALFORMED", "request aborted");
      res.on("finish", () => req.destroy());
      return fail(res, 413, "TOO_LARGE", "control body ceiling breached");
    }
    const action = parseControl(read.body);
    if (action === null) return fail(res, 400, "SCHEMA", "unrecognised control action");

    const now = Date.now();
    switch (action.op) {
      case "PAUSE":
        runtime.setPaused(true);
        return json(res, 200, { ok: true, applied: "PAUSE" });
      case "RESUME":
        runtime.setPaused(false);
        return json(res, 200, { ok: true, applied: "RESUME" });
      case "RATE":
        runtime.setRate(action.tps);
        return json(res, 200, { ok: true, applied: `RATE=${action.tps}` });
      case "SCENARIO":
        runtime.runScenario(action.name, 20);
        return json(res, 200, { ok: true, applied: `SCENARIO=${action.name}` });
      case "RELEASE": {
        const done = runtime.arbiter.release(action.su, now);
        return done
          ? json(res, 200, { ok: true, applied: `RELEASE=${action.su}` })
          : fail(res, 404, "NOT_FOUND", "subject not tracked");
      }
      case "FLAG": {
        const done = runtime.arbiter.forceFlag(action.su, now);
        return done
          ? json(res, 200, { ok: true, applied: `FLAG=${action.su}` })
          : fail(res, 404, "NOT_FOUND", "subject not tracked");
      }
      default:
        return fail(res, 400, "SCHEMA", "unrecognised control action");
    }
  }

  if (pathname === "/v1/request") {
    if (method !== "POST") return fail(res, 405, "BAD_METHOD", "POST required");
    if (!originAllowed(req, config.consoleOrigins)) return fail(res, 403, "FORBIDDEN", "origin refused");

    // Same content-type discipline as ingest: the classic cross-site form shapes are
    // not parseable here either, so a cross-site POST cannot even reach the parser.
    const ctype = header(req, "content-type");
    if (ctype === null || !ctype.toLowerCase().startsWith("application/json")) {
      return fail(res, 415, "BAD_CT", "application/json required");
    }
    const declared = Number(header(req, "content-length") ?? "0");
    if (Number.isFinite(declared) && declared > REQUEST_LIMITS.bodyBytes) {
      return fail(res, 413, "TOO_LARGE", "declared body exceeds ceiling");
    }

    const read = await readBody(req, REQUEST_LIMITS.bodyBytes);
    if (!read.ok) {
      if (read.reason === "ABORTED") return fail(res, 400, "MALFORMED", "request aborted before the body completed");
      res.on("finish", () => req.destroy());
      return fail(res, 413, "TOO_LARGE", "body ceiling breached");
    }

    const outcome = await runtime.requests.submit(read.body, sourceOf(req), Date.now());
    if (!outcome.ok) return fail(res, STATUS_OF[outcome.code], outcome.code, outcome.msg);

    // 202, not 200: the payload is an acknowledgement, not a delivery receipt. Whether
    // the relay actually delivered is operator information and lives in the ledger.
    return json(res, 202, { ok: true, ref: outcome.ref });
  }

  /* ---------------- accounts, subscriptions, uploads, administration ---------------- */

  // Placed after the telemetry and control surfaces and before the console fallback, so
  // these routes are reached only by an exact method-and-path match. A path this module
  // owns with a verb it does not accept is answered 405 inside the module.
  if (ownsAccountPath(pathname)) {
    await handleAccountRoutes({ req, res, pathname, method, config });
    return;
  }

  /* ---------------- static console ---------------- */

  if (pathname.startsWith("/v1/")) return fail(res, 404, "NOT_FOUND", "no such endpoint");
  if (method !== "GET" && method !== "HEAD") return fail(res, 405, "BAD_METHOD", "GET required");

  if (config.staticDir === null) {
    return send(
      res,
      200,
      [
        "ARES arbiter",
        "",
        "status   : listening (API only)",
        "console  : served by the Vite dev server in development",
        "           build with `npm run build`, then start with `--serve-static=dist`",
        "endpoints: POST /v1/ingest | GET /v1/stream | GET /v1/snapshot",
        "           GET /v1/subject/<tag> | GET /v1/health | POST /v1/control",
        "           POST /v1/request  (public build-request intake)",
        "",
      ].join("\n"),
      "text/plain; charset=utf-8",
      method === "HEAD",
    );
  }

  return serveStatic(config.staticDir, pathname, res, method === "HEAD");
}

function serveStatic(root: string, pathname: string, res: ServerResponse, head: boolean): void {
  const base = path.resolve(root);
  const wanted = pathname === "/" ? "index.html" : pathname.replace(/^\/+/, "");
  const resolved = path.resolve(base, wanted);
  // Containment: a decoded "../" must not escape the asset root.
  if (resolved !== base && !resolved.startsWith(base + path.sep)) {
    return fail(res, 403, "FORBIDDEN", "path outside asset root");
  }

  let target = resolved;
  try {
    if (statSync(target).isDirectory()) target = path.join(target, "index.html");
  } catch {
    // Single-page application fallback: unknown asset paths resolve to the shell.
    target = path.join(base, "index.html");
  }

  let size = 0;
  try {
    const stat = statSync(target);
    if (!stat.isFile()) throw new Error("not a file");
    size = stat.size;
  } catch {
    return fail(res, 404, "NOT_FOUND", "asset not found");
  }

  const ext = path.extname(target).toLowerCase();
  const type = CONTENT_TYPES[ext] ?? "application/octet-stream";
  res.writeHead(200, {
    "Content-Type": type,
    "Content-Length": String(size),
    "Cache-Control": ext === ".html" ? "no-store" : "public, max-age=31536000, immutable",
    ...SECURITY_HEADERS,
  });
  if (head) {
    res.end();
    return;
  }
  createReadStream(target).pipe(res);
}
