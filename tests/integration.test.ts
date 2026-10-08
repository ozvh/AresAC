/**
 * End-to-end tests over the real HTTP surface.
 *
 * These do not call the arbiter directly: they open sockets, sign payloads, and
 * assert on status codes and state, exactly as a reporting agent and an operator
 * console would. A defence that only holds when called in-process is not a defence.
 */
import assert from "node:assert/strict";
import { after, before, test } from "node:test";
import type { AddressInfo } from "node:net";
import {
  LIMITS,
  PROTOCOL_VERSION,
  canonicalEvent,
  type EvidenceCode,
  type IngestEvent,
  type Role,
  type SnapshotResponse,
} from "../shared/protocol.ts";
import { AgentRegistry, signEvent, type Agent } from "../server/agents.ts";
import { Fleet } from "../server/fleet.ts";
import { createArbiterServer } from "../server/http.ts";
import { Ledger } from "../server/ledger.ts";
import { Arbiter, TUNING } from "../server/machine.ts";
import type { Runtime } from "../server/runtime.ts";
import { Broadcaster } from "../server/sse.ts";
import { testRuntime } from "./harness.ts";

const OPERATOR_TOKEN = "a".repeat(48);
const SUBJECT = "1a2b3c4d5e6f".repeat(3).slice(0, 32);

type Harness = {
  base: string;
  registry: AgentRegistry;
  runtime: Runtime;
};

let harness: Harness;
let server: ReturnType<typeof createArbiterServer>;
let seq = 0;

before(async () => {
  const registry = new AgentRegistry(Buffer.alloc(32, 11));
  const ledger = new Ledger();
  const arbiter = new Arbiter(ledger);
  const bus = new Broadcaster(LIMITS.replayRing);
  const fleet = new Fleet(registry, { sessions: 2, tps: 0, origin: "http://127.0.0.1:1", seed: 1 });
  const runtime = testRuntime({ arbiter, ledger, bus, registry, fleet, operatorToken: OPERATOR_TOKEN });

  server = createArbiterServer({
    runtime,
    consoleOrigins: ["http://127.0.0.1:5173"],
    staticDir: null,
  });

  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
  const address = server.address() as AddressInfo;
  const base = `http://127.0.0.1:${address.port}`;
  fleet.setOrigin(base);
  runtime.start();
  harness = { base, registry, runtime };
});

after(async () => {
  harness.runtime.stop();
  await new Promise<void>((resolve) => server.close(() => resolve()));
});

function makeEvents(agent: Agent, role: Role, code: EvidenceCode, count = 1, subject = SUBJECT): IngestEvent[] {
  const ring = role === "KMOD" ? 0 : role === "UMON" ? 3 : -1;
  const events: IngestEvent[] = [];
  for (let i = 0; i < count; i += 1) {
    seq += 1;
    events.push({ v: PROTOCOL_VERSION, a: agent.id, k: subject, s: seq, t: Date.now(), r: ring, c: code, m: 1 });
  }
  return events;
}

async function post(events: IngestEvent[], agent: Agent, overrides: Record<string, string> = {}): Promise<Response> {
  const canonical = events.map((e) => canonicalEvent(e)).join("\n");
  return fetch(`${harness.base}/v1/ingest`, {
    method: "POST",
    headers: {
      "content-type": "application/json",
      "x-zeus-sig": signEvent(agent.key, canonical),
      ...overrides,
    },
    body: JSON.stringify(events),
  });
}

async function snapshot(): Promise<SnapshotResponse> {
  const res = await fetch(`${harness.base}/v1/snapshot`);
  assert.equal(res.status, 200);
  return (await res.json()) as SnapshotResponse;
}

function report(response: Response): Promise<{ e?: string }> {
  return response.json() as Promise<{ e?: string }>;
}

/* ------------------------------------------------------------------ */
/*  Authentication and provenance                                      */
/* ------------------------------------------------------------------ */

test("a signed batch is accepted and becomes observable state", async () => {
  const monitor = harness.registry.enroll("UMON");
  const res = await post(makeEvents(monitor, "UMON", "XB", 4), monitor);
  assert.equal(res.status, 202);
  const accepted = await snapshot();
  assert.ok(accepted.subjects.length > 0);
  assert.ok(accepted.counters.rx >= 4);
});

test("an unsigned batch is refused", async () => {
  const monitor = harness.registry.enroll("UMON");
  const events = makeEvents(monitor, "UMON", "XB");
  const res = await fetch(`${harness.base}/v1/ingest`, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify(events),
  });
  assert.equal(res.status, 401);
  assert.equal((await report(res)).e, "SIG");
});

test("a tampered payload is refused even with a valid signature shape", async () => {
  const monitor = harness.registry.enroll("UMON");
  const events = makeEvents(monitor, "UMON", "XB");
  const canonical = events.map((e) => canonicalEvent(e)).join("\n");
  const mac = signEvent(monitor.key, canonical);
  const mutated = events.map((e) => ({ ...e, c: "X3" }));
  const res = await fetch(`${harness.base}/v1/ingest`, {
    method: "POST",
    headers: { "content-type": "application/json", "x-zeus-sig": mac },
    body: JSON.stringify(mutated),
  });
  assert.equal(res.status, 401);
});

test("an unenrolled agent id is refused", async () => {
  const impostor: Agent = { id: "f".repeat(16), role: "UMON", key: Buffer.alloc(32, 1) };
  const events = makeEvents(impostor, "UMON", "XB");
  const res = await post(events, impostor);
  assert.equal(res.status, 401);
});

test("a replayed sequence is refused", async () => {
  const monitor = harness.registry.enroll("UMON");
  // The same frame is submitted twice: the second must not buy a second verdict.
  const events = makeEvents(monitor, "UMON", "XB");
  assert.equal((await post(events, monitor)).status, 202);
  const replay = await post(events, monitor);
  assert.equal(replay.status, 409);
  assert.equal((await report(replay)).e, "REPLAY");
});

test("a forged ring claim is refused, and the attempt is counted", async () => {
  const monitor = harness.registry.enroll("UMON");
  const before = (await snapshot()).counters.spf;
  // XC is a kernel-only code; a user-mode principal claiming it is forging depth.
  const res = await post(makeEvents(monitor, "UMON", "XC"), monitor);
  assert.equal(res.status, 403);
  assert.equal((await report(res)).e, "ROLE");

  const forgedRing = makeEvents(monitor, "UMON", "XB");
  const declared = forgedRing.map((e) => ({ ...e, r: 0 as const }));
  const res2 = await post(declared, monitor);
  assert.equal(res2.status, 403, "declaring the kernel ring from a user-mode agent is refused");

  const after = (await snapshot()).counters.spf;
  assert.equal(after, before + 2, "both attempts must be visible in the counters");
});

test("a batch spanning two principals is refused", async () => {
  const a = harness.registry.enroll("UMON");
  const b = harness.registry.enroll("UMON");
  const events = [...makeEvents(a, "UMON", "XB"), ...makeEvents(b, "UMON", "XB")];
  const res = await post(events, a);
  assert.equal(res.status, 400);
});

/* ------------------------------------------------------------------ */
/*  Transport hardening                                                */
/* ------------------------------------------------------------------ */

test("a cross-origin browser request is refused", async () => {
  const monitor = harness.registry.enroll("UMON");
  const res = await post(makeEvents(monitor, "UMON", "XB"), monitor, { origin: "https://evil.example" });
  assert.equal(res.status, 403);
  assert.equal((await report(res)).e, "FORBIDDEN");
});

test("the configured console origin is permitted", async () => {
  const monitor = harness.registry.enroll("UMON");
  const res = await post(makeEvents(monitor, "UMON", "XB"), monitor, { origin: "http://127.0.0.1:5173" });
  assert.equal(res.status, 202);
});

test("a non-JSON content type is refused without being parsed", async () => {
  const monitor = harness.registry.enroll("UMON");
  const events = makeEvents(monitor, "UMON", "XB");
  const res = await fetch(`${harness.base}/v1/ingest`, {
    method: "POST",
    headers: { "content-type": "text/plain", "x-zeus-sig": signEvent(monitor.key, events.map(canonicalEvent).join("\n")) },
    body: JSON.stringify(events),
  });
  assert.equal(res.status, 415);
});

test("a declared oversized body is refused before it is read", async () => {
  const res = await fetch(`${harness.base}/v1/ingest`, {
    method: "POST",
    headers: { "content-type": "application/json", "x-zeus-sig": "0".repeat(64) },
    body: "x".repeat(LIMITS.bodyBytes + 1024),
  });
  assert.equal(res.status, 413);
  assert.equal((await report(res)).e, "TOO_LARGE");
});

test("a streamed body without a declared length still trips the byte ceiling", async () => {
  const chunk = new Uint8Array(4 * 1024).fill(120);
  let sent = 0;
  const stream = new ReadableStream<Uint8Array>({
    pull(controller) {
      if (sent >= LIMITS.bodyBytes + 8 * 1024) {
        controller.close();
        return;
      }
      sent += chunk.length;
      controller.enqueue(chunk);
    },
  });
  const res = await fetch(`${harness.base}/v1/ingest`, {
    method: "POST",
    headers: { "content-type": "application/json", "x-zeus-sig": "0".repeat(64) },
    body: stream,
    // Required by undici for a streaming request body.
    duplex: "half",
  } as RequestInit & { duplex: "half" });
  assert.equal(res.status, 413, "the counting cap must fire without a Content-Length header");
});

test("an unknown endpoint under the API prefix is not silently served the console", async () => {
  const res = await fetch(`${harness.base}/v1/nope`);
  assert.equal(res.status, 404);
});

/* ------------------------------------------------------------------ */
/*  Operator control plane                                             */
/* ------------------------------------------------------------------ */

test("control requires the operator token and is throttled", async () => {
  const body = JSON.stringify({ op: "PAUSE" });
  const unauthorised = await fetch(`${harness.base}/v1/control`, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body,
  });
  assert.equal(unauthorised.status, 403);

  const authorised = await fetch(`${harness.base}/v1/control`, {
    method: "POST",
    headers: { "content-type": "application/json", "x-zeus-op": OPERATOR_TOKEN },
    body,
  });
  assert.equal(authorised.status, 200);

  const throttled = await fetch(`${harness.base}/v1/control`, {
    method: "POST",
    headers: { "content-type": "application/json", "x-zeus-op": OPERATOR_TOKEN },
    body: JSON.stringify({ op: "RESUME" }),
  });
  assert.equal(throttled.status, 429, "two mutations in one interval must not both land");

  await new Promise((resolve) => setTimeout(resolve, LIMITS.controlMinIntervalMs + 120));
  const resumed = await fetch(`${harness.base}/v1/control`, {
    method: "POST",
    headers: { "content-type": "application/json", "x-zeus-op": OPERATOR_TOKEN },
    body: JSON.stringify({ op: "RESUME" }),
  });
  assert.equal(resumed.status, 200);
});

test("an unrecognised control action is refused", async () => {
  await new Promise((resolve) => setTimeout(resolve, LIMITS.controlMinIntervalMs + 120));
  const res = await fetch(`${harness.base}/v1/control`, {
    method: "POST",
    headers: { "content-type": "application/json", "x-zeus-op": OPERATOR_TOKEN },
    body: JSON.stringify({ op: "DROP_ALL_TABLES" }),
  });
  assert.equal(res.status, 400);
});

/* ------------------------------------------------------------------ */
/*  The conviction pipeline, end to end                                */
/* ------------------------------------------------------------------ */

test("a two-ring cheat is convicted, sealed, then released by the operator", async () => {
  const monitor = harness.registry.enroll("UMON");
  const driver = harness.registry.enroll("KMOD");
  // This case owns its subject so its evidence ledger stays unambiguous.
  const cheat = "9d" + "0".repeat(30);
  const tag = cheat.slice(0, 12);

  // Structural proof from the user-mode sentinel, then corroboration from the driver.
  assert.equal((await post(makeEvents(monitor, "UMON", "X1", 1, cheat), monitor)).status, 202);
  assert.equal((await post(makeEvents(driver, "KMOD", "X6", 1, cheat), driver)).status, 202);

  // Immediately after the sample lands: high suspicion, capability already denied,
  // but no conviction — the dwell requirement has not matured yet.
  const immediate = await snapshot();
  const pending = immediate.subjects.find((s) => s.su === tag);
  assert.ok(pending, `subject ${tag} must appear in state`);
  assert.equal(pending.vd, "PENDING", `expected PENDING, saw ${JSON.stringify(pending)}`);
  assert.equal(pending.ct, true, "the capability is denied before the account is touched");
  assert.equal(pending.rm, 3, "both reporting rings must be recorded as corroborating");

  // The arbiter's own sweeper must mature the dwell requirement; nothing here
  // advances time by hand.
  await new Promise((resolve) => setTimeout(resolve, TUNING.dwellMs + 1_200));

  const convicted = await snapshot();
  const subject = convicted.subjects.find((s) => s.su === tag);
  assert.ok(subject, "the subject must appear in state");
  assert.equal(subject.vd, "FLAGGED", `expected FLAGGED, saw ${JSON.stringify(subject)}`);
  assert.equal(subject.st, "CONVICT");
  assert.equal(subject.rm, 3, "both reporting rings must be recorded");

  const detail = await fetch(`${harness.base}/v1/subject/${tag}`);
  assert.equal(detail.status, 200);
  const detailBody = (await detail.json()) as { codes: Array<{ c: string; n: number }> };
  assert.deepEqual(
    detailBody.codes.map((c) => c.c).sort(),
    ["X1", "X6"],
  );

  assert.equal(convicted.chain.broken, false);

  await new Promise((resolve) => setTimeout(resolve, LIMITS.controlMinIntervalMs + 120));
  const released = await fetch(`${harness.base}/v1/control`, {
    method: "POST",
    headers: { "content-type": "application/json", "x-zeus-op": OPERATOR_TOKEN },
    body: JSON.stringify({ op: "RELEASE", su: tag }),
  });
  assert.equal(released.status, 200);

  const after = await snapshot();
  const cleared = after.subjects.find((s) => s.su === tag);
  assert.ok(cleared);
  assert.equal(cleared.vd, "CLEAN");
  assert.ok(after.ledger.some((r) => r.kind === "RELEASE"), "the release must be sealed into the chain");
});

test("the detail endpoint refuses malformed and unknown subject tags", async () => {
  assert.equal((await fetch(`${harness.base}/v1/subject/nope`)).status, 400);
  assert.equal((await fetch(`${harness.base}/v1/subject/001122334455`)).status, 404);
});

/* ------------------------------------------------------------------ */
/*  The live stream                                                    */
/* ------------------------------------------------------------------ */

test("the stream delivers state frames and reports its position", async () => {
  const controller = new AbortController();
  const res = await fetch(`${harness.base}/v1/stream`, { signal: controller.signal });
  assert.equal(res.status, 200);
  assert.match(res.headers.get("content-type") ?? "", /text\/event-stream/);
  assert.equal(res.headers.get("cache-control"), "no-store, no-cache, must-revalidate");

  const reader = res.body?.getReader();
  assert.ok(reader, "a stream body must be readable");
  const decoder = new TextDecoder();
  let buffered = "";
  const deadline = Date.now() + 4_000;

  while (Date.now() < deadline && !buffered.includes('"k":"S"')) {
    const next = await reader.read();
    if (next.done) break;
    buffered += decoder.decode(next.value, { stream: true });
  }
  controller.abort();

  assert.match(buffered, /^retry: \d+/m, "the console is told how to reconnect");
  assert.match(buffered, /^id: \d+/m, "frames carry a resumable id");
  assert.match(buffered, /event: f/);
  assert.ok(buffered.includes('"k":"S"'), "a state frame must arrive");
});

test("the health endpoint reports a verified chain", async () => {
  const res = await fetch(`${harness.base}/v1/health`);
  assert.equal(res.status, 200);
  const body = (await res.json()) as { ok: boolean; chainOk: boolean; accepted: number };
  assert.equal(body.ok, true);
  assert.equal(body.chainOk, true);
  assert.ok(body.accepted > 0);
});
