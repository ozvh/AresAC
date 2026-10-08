/**
 * Build-request intake tests.
 *
 * Two things are being proved here, and neither is "the form works".
 *
 * The first is that the public surface cannot be turned against the deployment. It is
 * the only endpoint that takes unauthenticated input and causes an outbound effect, so
 * the assertions that matter are the hostile ones: an unmodelled field, a fabricated
 * destination, a header-injection attempt, a spray from one source.
 *
 * The second is that a stranger's request is never silently lost. A relay that is
 * unconfigured, refusing, or unreachable must still leave the request recoverable — and
 * the operator must be able to tell the three apart, which is why every relay outcome is
 * sealed into the ledger with its own name.
 *
 * The relay is a real HTTP server rather than a stubbed fetch: the wire shape, the
 * bearer header and the body sanitisation are what is under test, and a stub would
 * assert only that the code calls itself.
 */
import assert from "node:assert/strict";
import { after, before, test } from "node:test";
import { createServer, type IncomingMessage, type Server } from "node:http";
import { statSync } from "node:fs";
import { mkdtemp, readFile } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import type { AddressInfo } from "node:net";
import { LIMITS, REQUEST_LIMITS, type RequestStats } from "../shared/protocol.ts";
import { createArbiterServer } from "../server/http.ts";
import { Ledger } from "../server/ledger.ts";
import { Mailer } from "../server/mailer.ts";
import { Arbiter } from "../server/machine.ts";
import { RequestIntake, parseBuildRequest } from "../server/requests.ts";
import { Broadcaster } from "../server/sse.ts";
import { AgentRegistry } from "../server/agents.ts";
import { Fleet } from "../server/fleet.ts";
import { testRuntime } from "./harness.ts";

const OPERATOR_TOKEN = "b".repeat(48);
const ORIGIN = "http://127.0.0.1:5173";

/* ------------------------------------------------------------------ */
/*  A relay that records what it was actually sent                     */
/* ------------------------------------------------------------------ */

type Captured = {
  readonly authorization: string | null;
  readonly contentType: string | null;
  readonly body: Record<string, unknown>;
};

type Relay = {
  readonly url: string;
  readonly captured: Captured[];
  setStatus(status: number): void;
  close(): Promise<void>;
};

async function startRelay(): Promise<Relay> {
  const captured: Captured[] = [];
  let status = 200;

  const server: Server = createServer((req: IncomingMessage, res) => {
    const chunks: Buffer[] = [];
    req.on("data", (chunk: Buffer) => chunks.push(chunk));
    req.on("end", () => {
      const raw = Buffer.concat(chunks).toString("utf8");
      let body: Record<string, unknown> = {};
      try {
        const parsed: unknown = JSON.parse(raw);
        if (typeof parsed === "object" && parsed !== null) body = parsed as Record<string, unknown>;
      } catch {
        body = { __unparseable: raw };
      }
      const auth = req.headers.authorization;
      const ct = req.headers["content-type"];
      captured.push({
        authorization: typeof auth === "string" ? auth : null,
        contentType: typeof ct === "string" ? ct : null,
        body,
      });
      res.writeHead(status, { "content-type": "application/json" });
      res.end(JSON.stringify({ id: "relay-message-id" }));
    });
  });

  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
  const address = server.address() as AddressInfo;
  return {
    url: `http://127.0.0.1:${address.port}/emails`,
    captured,
    setStatus: (next: number) => {
      status = next;
    },
    close: () => new Promise<void>((resolve) => server.close(() => resolve())),
  };
}

/* ------------------------------------------------------------------ */
/*  Isolated intake instances                                          */
/* ------------------------------------------------------------------ */

type Harness = {
  intake: RequestIntake;
  mailer: Mailer;
  ledger: Ledger;
  spool: string;
  relay: Relay;
};

let spoolDir = "";
let relay: Relay;

/**
 * One setup hook for the whole file.
 *
 * Deliberately one: Node runs top-level hooks concurrently rather than in registration
 * order, so a second `before` that needed the relay from the first would start before it
 * had a relay. Everything this suite needs is therefore established in a single place.
 */
before(async () => {
  spoolDir = await mkdtemp(path.join(os.tmpdir(), "ares-request-"));
  relay = await startRelay();

  // A forwarded address is only honoured when the operator has declared a proxy, so
  // declaring one here is what lets each HTTP request below be charged to its own
  // source rather than to the socket every request shares.
  process.env["ARES_TRUST_PROXY"] = "1";

  const registry = new AgentRegistry(Buffer.alloc(32, 7));
  const ledger = new Ledger();
  const arbiter = new Arbiter(ledger);
  const bus = new Broadcaster(LIMITS.replayRing);
  const fleet = new Fleet(registry, { sessions: 1, tps: 0, origin: "http://127.0.0.1:1", seed: 2 });
  // The runtime's own intake, so the counters this suite asserts on are the counters the
  // HTTP route actually moved.
  const runtime = testRuntime({
    arbiter,
    ledger,
    bus,
    registry,
    fleet,
    operatorToken: OPERATOR_TOKEN,
    relay: { apiKey: "test-key", endpoint: relay.url, recipient: "cagelove094@gmail.com" },
    spoolPath: path.join(spoolDir, "http-spool.log"),
  });

  httpServer = createArbiterServer({ runtime, consoleOrigins: [ORIGIN], staticDir: null });
  await new Promise<void>((resolve) => httpServer.listen(0, "127.0.0.1", resolve));
  const address = httpServer.address() as AddressInfo;
  http = { base: `http://127.0.0.1:${address.port}`, intake: runtime.requests, ledger };
});

after(async () => {
  delete process.env["ARES_TRUST_PROXY"];
  await new Promise<void>((resolve) => httpServer.close(() => resolve()));
  await relay.close();
});

/**
 * A fresh intake over the shared recording relay. Each test that reasons about counters
 * or velocity gets its own, because a shared velocity budget makes tests order-dependent
 * and order-dependent tests hide real bugs.
 */
function harness(overrides: { apiKey?: string; endpoint?: string; recipient?: string; from?: string } = {}): Harness {
  const ledger = new Ledger();
  const spool = path.join(spoolDir, `spool-${Math.random().toString(16).slice(2)}.log`);
  const mailer = new Mailer({
    apiKey: overrides.apiKey ?? "test-key",
    from: overrides.from ?? "ARES Arbiter <onboarding@resend.dev>",
    recipient: overrides.recipient ?? "cagelove094@gmail.com",
    endpoint: overrides.endpoint ?? relay.url,
    spoolPath: spool,
    timeoutMs: 2_000,
  });
  return { intake: new RequestIntake({ mailer, ledger }), mailer, ledger, spool, relay };
}

function payload(overrides: Record<string, unknown> = {}): string {
  return JSON.stringify({
    nm: "operator",
    em: "requester@example.com",
    org: "example works",
    tgt: "RETAIL",
    msg: "requesting a build for a private server, roughly forty players.",
    hp: "",
    el: REQUEST_LIMITS.dwellMs + 500,
    ...overrides,
  });
}

function refusal(outcome: Awaited<ReturnType<RequestIntake["submit"]>>): { code: string; msg: string } {
  if (outcome.ok) throw new Error("expected a refusal, got an acceptance");
  return { code: outcome.code, msg: outcome.msg };
}

/** Sealed records of one kind, read back from the retained window. */
function sealedRequests(ledger: Ledger): string[] {
  return ledger
    .recordsView()
    .filter((record) => record.kind === "REQUEST")
    .map((record) => record.dt);
}

/* ------------------------------------------------------------------ */
/*  Shape: the closed key set on a public endpoint                     */
/* ------------------------------------------------------------------ */

test("a well-formed submission parses into exactly the modelled fields", () => {
  const parsed = parseBuildRequest(payload());
  assert.equal(parsed.ok, true);
  if (!parsed.ok) return;
  assert.equal(Object.keys(parsed.input).length, 7);
  assert.equal(parsed.input.tgt, "RETAIL");
  assert.equal(parsed.input.hp, "");
});

test("an unmodelled field is refused outright", () => {
  // The classic attempt to smuggle a destination address in beside the modelled fields.
  const parsed = parseBuildRequest(payload({ to: "attacker@evil.example" }));
  assert.equal(parsed.ok, false);
  if (parsed.ok) return;
  assert.equal(parsed.code, "SCHEMA");
  assert.match(parsed.msg, /field count/);
});

test("a missing field is refused rather than defaulted", () => {
  // One field short: caught by the count before anything is read.
  const short = parseBuildRequest(
    JSON.stringify({ nm: "abc", em: "b@c.com", org: "", tgt: "RETAIL", msg: "long enough", hp: "" }),
  );
  assert.equal(short.ok, false);
  if (short.ok) return;
  assert.match(short.msg, /field count 6/);

  // The right count with the wrong names: an own "__proto__" key satisfies the count
  // while a modelled field is actually absent. The presence walk is what catches this,
  // and the field must not fall back to a default on the way.
  const shadowed = parseBuildRequest(
    '{"__proto__":"x","em":"b@c.com","org":"","tgt":"RETAIL","msg":"long enough","hp":"","el":3000}',
  );
  assert.equal(shadowed.ok, false);
  if (shadowed.ok) return;
  assert.match(shadowed.msg, /missing field nm/);
});

test("a control character in a header-bound field is refused", () => {
  const parsed = parseBuildRequest(payload({ org: "example\r\nBcc: victim@example.com" }));
  assert.equal(parsed.ok, false);
  if (parsed.ok) return;
  assert.match(parsed.msg, /control characters/);
});

test("a note may span several lines but may not carry other control bytes", () => {
  const allowed = parseBuildRequest(payload({ msg: "line one\n\nline two, still a real request." }));
  assert.equal(allowed.ok, true);
  if (allowed.ok) assert.match(allowed.input.msg, /\n/);

  const refused = parseBuildRequest(payload({ msg: "line one\u0000line two" }));
  assert.equal(refused.ok, false);
});

test("an unknown build channel is refused", () => {
  const parsed = parseBuildRequest(payload({ tgt: "WHATEVER_PLEASE" }));
  assert.equal(parsed.ok, false);
  if (parsed.ok) return;
  assert.match(parsed.msg, /build channel/);
});

test("an address that is not an address is refused", () => {
  for (const candidate of ["nobody", "nobody@", "@example.com", "a b@example.com", "nobody@localhost"]) {
    const parsed = parseBuildRequest(payload({ em: candidate }));
    assert.equal(parsed.ok, false, `expected ${candidate} to be refused`);
  }
});

test("a note under the floor and a body that is not JSON are refused", () => {
  assert.equal(parseBuildRequest(payload({ msg: "hi" })).ok, false);
  const malformed = parseBuildRequest("not json at all");
  assert.equal(malformed.ok, false);
  if (malformed.ok) return;
  assert.equal(malformed.code, "MALFORMED");
});

test("a body over the ceiling is refused on size, not parsed", () => {
  const huge = payload({ msg: "x".repeat(REQUEST_LIMITS.noteMax) });
  const padded = `${huge}${" ".repeat(REQUEST_LIMITS.bodyBytes)}`;
  const parsed = parseBuildRequest(padded);
  assert.equal(parsed.ok, false);
  if (parsed.ok) return;
  assert.equal(parsed.code, "TOO_LARGE");
});

/* ------------------------------------------------------------------ */
/*  Policy: honeypot, dwell, velocity, dedupe                           */
/* ------------------------------------------------------------------ */

test("the honeypot refuses the submission and seals nothing", async () => {
  const h = harness();
  const now = Date.now();
  const outcome = await h.intake.submit(payload({ hp: "http://spam.example" }), "10.0.0.1", now);
  assert.equal(refusal(outcome).code, "SCHEMA");
  assert.equal(h.intake.stats().trapped, 1);
  assert.equal(h.intake.stats().accepted, 0);
  // An anonymous caller must not be able to write into the audit tail.
  assert.equal(sealedRequests(h.ledger).length, 0);
  assert.equal(relay.captured.length, 0);
});

test("a submission that cannot have rendered a page is refused", async () => {
  const h = harness();
  const now = Date.now();
  const outcome = await h.intake.submit(payload({ el: REQUEST_LIMITS.dwellMs - 1 }), "10.0.0.2", now);
  assert.equal(refusal(outcome).code, "SCHEMA");
  assert.equal(sealedRequests(h.ledger).length, 0);
});

test("one source cannot outspend its own velocity budget", async () => {
  const h = harness();
  // A frozen clock makes this deterministic: no token can refill between attempts, so
  // the ceiling is a property of the limits rather than of how fast the test machine is.
  const now = 1_700_000_000_000;

  const first = await h.intake.submit(payload({ em: "one@example.com" }), "10.0.0.3", now);
  const second = await h.intake.submit(payload({ em: "two@example.com" }), "10.0.0.3", now);
  const third = await h.intake.submit(payload({ em: "three@example.com" }), "10.0.0.3", now);

  assert.equal(first.ok, true);
  assert.equal(second.ok, true);
  assert.equal(refusal(third).code, "RATE");
  assert.equal(h.intake.stats().throttled, 1);
});

test("a distinct source is not punished for another source's spending", async () => {
  const h = harness();
  const now = 1_700_000_000_000;
  await h.intake.submit(payload({ em: "one@example.com" }), "10.0.0.4", now);
  await h.intake.submit(payload({ em: "two@example.com" }), "10.0.0.4", now);
  assert.equal(refusal(await h.intake.submit(payload({ em: "x@example.com" }), "10.0.0.4", now)).code, "RATE");
  // A different source still has its own budget available.
  assert.equal((await h.intake.submit(payload({ em: "x@example.com" }), "10.0.0.5", now)).ok, true);
});

test("a repeated request from one source folds into the original reference", async () => {
  const h = harness();
  const now = 1_700_000_000_000;
  const first = await h.intake.submit(payload(), "10.0.0.6", now);
  assert.equal(first.ok, true);
  if (!first.ok) return;

  const before = relay.captured.length;
  const again = await h.intake.submit(payload(), "10.0.0.6", now + 1_000);
  assert.equal(again.ok, true);
  if (!again.ok) return;

  assert.equal(again.ref, first.ref, "a duplicate must answer with the original reference");
  assert.equal(relay.captured.length, before, "a duplicate must not be relayed twice");
  assert.equal(h.intake.stats().duplicates, 1);
  assert.equal(sealedRequests(h.ledger).length, 1);
});

test("an identical request from a different source is a separate request", async () => {
  const h = harness();
  const now = 1_700_000_000_000;
  await h.intake.submit(payload(), "10.0.0.7", now);
  await h.intake.submit(payload(), "10.0.0.8", now);
  assert.equal(sealedRequests(h.ledger).length, 2);
});

test("the process-wide budget caps a spray spread across many sources", async () => {
  const h = harness();
  // Distinct sources defeat the per-source bucket by construction; only the global
  // bucket stands between a distributed spray and the relay's quota.
  const now = 1_700_000_000_000;
  const attempts = REQUEST_LIMITS.globalBurst + 30;
  let accepted = 0;
  for (let i = 0; i < attempts; i += 1) {
    const outcome = await h.intake.submit(payload({ em: `s${i}@example.com` }), `10.2.0.${i}`, now);
    if (outcome.ok) accepted += 1;
  }
  assert.equal(accepted, REQUEST_LIMITS.globalBurst);
  assert.equal(h.intake.stats().throttled, attempts - REQUEST_LIMITS.globalBurst);
  assert.equal(h.intake.stats().trapped + h.intake.stats().refused, 0);
});

test("the dedupe table is reclaimed once its entries expire", async () => {
  const h = harness();
  let now = 1_700_000_000_000;
  // Sixty seconds between submissions is enough for the global bucket to refill, so
  // this is a trickle rather than a spray and every attempt should be admitted.
  for (let i = 0; i < 40; i += 1) {
    now += 60_000;
    const outcome = await h.intake.submit(payload({ em: `t${i}@example.com` }), `10.3.0.${i}`, now);
    assert.equal(outcome.ok, true, `attempt ${i} was refused`);
  }
  assert.equal(h.intake.trackedSources, 40, "every admitted request must be remembered for dedupe");
  assert.equal(h.intake.prune(now + REQUEST_LIMITS.dedupeMs + 1), 40);
  assert.equal(h.intake.trackedSources, 0);
  assert.ok(
    REQUEST_LIMITS.dedupeCap >= 40,
    "the hard cap must exceed anything the velocity gates can admit inside the window",
  );
});

/* ------------------------------------------------------------------ */
/*  Relay: destination, headers, and never losing a request             */
/* ------------------------------------------------------------------ */

test("the destination address comes from configuration and never from the payload", async () => {
  const h = harness();
  const before = relay.captured.length;
  const outcome = await h.intake.submit(payload({ em: "requester@example.com" }), "10.0.0.9", Date.now());
  assert.equal(outcome.ok, true);

  const sent = relay.captured[before];
  assert.ok(sent !== undefined, "the relay must have received the message");
  assert.deepEqual(sent.body["to"], ["cagelove094@gmail.com"]);
  // The requester's own address is a reply-to, which is the only thing it is trusted for.
  assert.equal(sent.body["reply_to"], "requester@example.com");
  assert.equal(sent.authorization, "Bearer test-key");
  assert.equal(sent.contentType, "application/json");
});

test("a configured recipient is the only address a request can reach", async () => {
  const h = harness({ recipient: "someone.else@example.org" });
  const before = relay.captured.length;
  await h.intake.submit(payload({ em: "requester@example.com" }), "10.0.0.10", Date.now());
  assert.deepEqual(relay.captured[before]?.body["to"], ["someone.else@example.org"]);
});

test("a header field cannot be made to carry a second header", async () => {
  const h = harness({ from: "ARES\r\nBcc: victim@example.com <onboarding@resend.dev>" });
  const before = relay.captured.length;
  await h.intake.submit(payload(), "10.0.0.11", Date.now());
  const sent = relay.captured[before];
  assert.ok(sent !== undefined);
  const from = sent.body["from"];
  assert.equal(typeof from, "string");
  // No CR/LF anywhere in any transmitted header field: with one, the relay emits two
  // messages and the second one goes wherever the submitter chose.
  for (const field of ["from", "subject", "reply_to"]) {
    assert.doesNotMatch(String(sent.body[field]), /[\r\n]/, `${field} carried a line break`);
  }
  for (const address of (sent.body["to"] as readonly string[] | undefined) ?? []) {
    assert.doesNotMatch(address, /[\r\n]/);
  }
});

test("a multi-line note survives intact to the relay", async () => {
  const h = harness();
  const before = relay.captured.length;
  const outcome = await h.intake.submit(
    payload({ msg: "first line\nsecond line, still a real request." }),
    "10.0.0.12",
    Date.now(),
  );
  assert.equal(outcome.ok, true, "a note with a line break is a normal note, not an attack");
  const text = String(relay.captured[before]?.body["text"]);
  assert.match(text, /first line\nsecond line/);
});

test("the relay neutralises a control byte it is handed directly", async () => {
  // The intake refuses a control byte outright, so this proves the second line of
  // defence: the transport sanitises whatever it is given, not only what the form sends.
  const h = harness();
  const before = relay.captured.length;
  const outcome = await h.mailer.deliver({
    to: h.mailer.recipient,
    from: h.mailer.from,
    replyTo: null,
    subject: "ares relay self-test",
    text: "first line\nsecond line\u0007broken",
  });
  assert.equal(outcome.relay, "DELIVERED");
  const text = String(relay.captured[before]?.body["text"]);
  assert.match(text, /first line\nsecond line/);
  assert.doesNotMatch(text, /\u0007/);
});

test("a refusal by the relay spools the request instead of losing it", async () => {
  const h = harness();
  relay.setStatus(422);
  const outcome = await h.intake.submit(payload(), "10.0.0.13", Date.now());
  relay.setStatus(200);

  assert.equal(outcome.ok, true, "a relay fault is not the requester's fault");
  assert.equal(h.intake.stats().spooled, 1);
  assert.equal(h.intake.stats().failed, 0);

  const spooled = await readFile(h.spool, "utf8");
  assert.match(spooled, /cagelove094@gmail\.com/);
  assert.match(spooled, /requester@example\.com/);

  // The operator must be able to tell a delivery from a spooling, which is the whole
  // reason the relay's verdict is sealed rather than swallowed.
  const records = sealedRequests(h.ledger);
  assert.equal(records.length, 1);
  assert.match(records[0] ?? "", /^REQ SPOOLED RETAIL /);
  // The address itself must not appear in the audit record the console renders.
  assert.doesNotMatch(records[0] ?? "", /requester@example\.com/);
});

test("an unreachable relay spools the request rather than dropping it", async () => {
  const h = harness({ endpoint: "http://127.0.0.1:1/emails" });
  const outcome = await h.intake.submit(payload(), "10.0.0.14", Date.now());
  assert.equal(outcome.ok, true);
  assert.equal(h.intake.stats().spooled, 1);
  assert.match((sealedRequests(h.ledger)[0] ?? ""), /^REQ SPOOLED /);
});

test("with no relay credential the request is spooled without touching the network", async () => {
  const h = harness({ apiKey: "" });
  const before = relay.captured.length;
  const outcome = await h.intake.submit(payload(), "10.0.0.15", Date.now());
  assert.equal(outcome.ok, true);
  assert.equal(h.intake.stats().spooled, 1);
  assert.equal(relay.captured.length, before, "no credential must mean no outbound attempt");
  assert.match((sealedRequests(h.ledger)[0] ?? ""), /^REQ SPOOLED /);
});

test("the spool is created readable by its owner alone", async () => {
  const h = harness({ apiKey: "" });
  await h.intake.submit(payload(), "10.0.0.16", Date.now());
  if (process.platform === "win32") return; // POSIX mode bits are not meaningful here.
  const mode = (await statSync(h.spool)).mode & 0o777;
  assert.equal(mode, 0o600, `spool mode was ${mode.toString(8)}`);
});

test("a delivered request seals its outcome and leaves the chain intact", async () => {
  const h = harness();
  await h.intake.submit(payload(), "10.0.0.17", Date.now());
  assert.equal(h.intake.stats().delivered, 1);
  assert.match((sealedRequests(h.ledger)[0] ?? ""), /^REQ DELIVERED RETAIL /);
  const verdict = h.ledger.verify();
  assert.equal(verdict.ok, true);
  assert.equal(h.ledger.status().broken, false);
});

/* ------------------------------------------------------------------ */
/*  Transport: the route over a real socket                             */
/* ------------------------------------------------------------------ */

type HttpHarness = { base: string; intake: RequestIntake; ledger: Ledger };

// Assigned by the single setup hook at the top of this file.
let http: HttpHarness;
let httpServer: ReturnType<typeof createArbiterServer>;

function post(raw: string, headers: Record<string, string> = {}): Promise<Response> {
  return fetch(`${http.base}/v1/request`, {
    method: "POST",
    headers: {
      "content-type": "application/json",
      origin: ORIGIN,
      "x-forwarded-for": `203.0.113.${Math.floor(Math.random() * 250) + 1}`,
      ...headers,
    },
    body: raw,
  });
}

test("the route answers 202 with a reference and seals one record", async () => {
  const sealedBefore = sealedRequests(http.ledger).length;
  const res = await post(payload());
  assert.equal(res.status, 202);
  const body = (await res.json()) as { ok: boolean; ref: string };
  assert.equal(body.ok, true);
  assert.match(body.ref, /^[0-9a-f]{8}$/);
  assert.equal(sealedRequests(http.ledger).length, sealedBefore + 1);
  // The acknowledgement must not leak how the request was relayed.
  assert.deepEqual(Object.keys(body).sort(), ["ok", "ref"]);
});

test("the route refuses a wrong method, wrong type, wrong origin and wrong shape", async () => {
  assert.equal((await fetch(`${http.base}/v1/request`)).status, 405);
  assert.equal((await post(payload(), { "content-type": "text/plain" })).status, 415);
  assert.equal((await post(payload(), { origin: "http://evil.example" })).status, 403);
  assert.equal((await post("}{")).status, 400);
  assert.equal((await post(payload({ tgt: "NOPE" }))).status, 400);
  assert.equal((await post(payload({ to: "attacker@evil.example" }))).status, 400);
});

test("the route refuses a body over its own smaller ceiling", async () => {
  const oversized = `${payload()}${" ".repeat(REQUEST_LIMITS.bodyBytes)}`;
  const res = await post(oversized, { "content-length": String(oversized.length) });
  assert.equal(res.status, 413);
});

test("the route throttles a source that keeps submitting", async () => {
  const source = "198.51.100.7";
  const first = await post(payload({ em: "one@example.com" }), { "x-forwarded-for": source });
  const second = await post(payload({ em: "two@example.com" }), { "x-forwarded-for": source });
  const third = await post(payload({ em: "three@example.com" }), { "x-forwarded-for": source });

  assert.equal(first.status, 202);
  assert.equal(second.status, 202);
  assert.equal(third.status, 429);
  assert.equal(((await third.json()) as { e: string }).e, "RATE");
});

test("a forwarded address is ignored unless a proxy has been declared", async () => {
  const sealedBefore = sealedRequests(http.ledger).length;
  const saved = process.env["ARES_TRUST_PROXY"];
  delete process.env["ARES_TRUST_PROXY"];
  try {
    // With no proxy declared both submissions key on the socket instead, so the second
    // folds into the first. A caller cannot choose its own bucket by inventing a header.
    const first = await post(payload({ em: "same@example.com" }), { "x-forwarded-for": "192.0.2.11" });
    const second = await post(payload({ em: "same@example.com" }), { "x-forwarded-for": "192.0.2.99" });
    assert.equal(first.status, 202);
    assert.equal(second.status, 202);
    const a = (await first.json()) as { ref: string };
    const b = (await second.json()) as { ref: string };
    assert.equal(b.ref, a.ref, "an undeclared forwarded address must not create a new source identity");
    assert.equal(sealedRequests(http.ledger).length, sealedBefore + 1);
  } finally {
    if (saved === undefined) delete process.env["ARES_TRUST_PROXY"];
    else process.env["ARES_TRUST_PROXY"] = saved;
  }
});

test("the health surface reports intake counters without requester data", async () => {
  const res = await fetch(`${http.base}/v1/health`);
  assert.equal(res.status, 200);
  const body = (await res.json()) as { requests: RequestStats };
  assert.equal(typeof body.requests.accepted, "number");
  assert.equal(typeof body.requests.trapped, "number");
  for (const value of Object.values(body.requests)) assert.equal(typeof value, "number");
  assert.doesNotMatch(JSON.stringify(body), /@example\.(com|org)/);
});

test("the ingest ceiling and the request ceiling are independent", () => {
  // A change to one must not silently widen the other.
  assert.ok(REQUEST_LIMITS.bodyBytes < LIMITS.bodyBytes);
  assert.equal(REQUEST_LIMITS.dwellMs, 2_000);
});
