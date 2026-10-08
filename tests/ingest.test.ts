/**
 * Boundary tests: everything that decides whether a hostile payload becomes
 * structured data. Each case here is a shape an attacker would actually try.
 */
import assert from "node:assert/strict";
import { test } from "node:test";
import { LIMITS, PROTOCOL_VERSION, type IngestEvent } from "../shared/protocol.ts";
import { AgentRegistry, signEvent, verifyMac } from "../server/agents.ts";
import { Ledger, sealRecord, verifyRecords } from "../server/ledger.ts";
import { Limiter, MAX_SKEW_MS } from "../server/limiter.ts";
import { parseIngest } from "../server/validate.ts";

const AGENT = "0123456789abcdef";
const SUBJECT = "f".repeat(32);

function event(overrides: Partial<Record<string, unknown>> = {}): Record<string, unknown> {
  return {
    v: PROTOCOL_VERSION,
    a: AGENT,
    k: SUBJECT,
    s: 1,
    t: 1_700_000_000_000,
    r: 3,
    c: "X7",
    m: 12.5,
    ...overrides,
  };
}

function accepted(raw: unknown): IngestEvent {
  const result = parseIngest(JSON.stringify(raw));
  assert.equal(result.ok, true, "expected the payload to be accepted");
  if (!result.ok) throw new Error("unreachable");
  const first = result.events[0];
  assert.ok(first);
  return first;
}

function rejected(raw: unknown): string {
  const result = parseIngest(JSON.stringify(raw));
  assert.equal(result.ok, false, "expected the payload to be rejected");
  if (result.ok) throw new Error("unreachable");
  return result.code;
}

/* ------------------------------------------------------------------ */
/*  Schema                                                             */
/* ------------------------------------------------------------------ */

test("a well-formed event is accepted and normalised", () => {
  const e = accepted(event());
  assert.equal(e.a, AGENT);
  assert.equal(e.c, "X7");
  assert.equal(e.r, 3);
});

test("an extra key is refused: no unmodelled field rides along", () => {
  assert.equal(rejected(event({ admin: true })), "SCHEMA");
  // Built as raw JSON on purpose: an object literal with `__proto__:` sets the
  // prototype, whereas JSON.parse creates a real own property that must be caught.
  const smuggled =
    `{"v":${PROTOCOL_VERSION},"a":"${AGENT}","k":"${SUBJECT}","s":1,"t":1700000000000,` +
    `"r":3,"c":"X7","m":1,"__proto__":{"admin":true}}`;
  const result = parseIngest(smuggled);
  assert.equal(result.ok, false);
  if (!result.ok) assert.equal(result.code, "SCHEMA");
});

test("a missing key is refused", () => {
  const partial = event();
  delete partial["m"];
  assert.equal(rejected(partial), "SCHEMA");
});

test("non-object events and non-JSON bodies are refused", () => {
  assert.equal(rejected([42]), "SCHEMA");
  assert.equal(rejected(["X7"]), "SCHEMA");
  assert.equal(parseIngest("{not json").ok, false);
  assert.equal(parseIngest("").ok, false);
});

test("wrong protocol version, unknown code, bad ring are refused", () => {
  assert.equal(rejected(event({ v: 99 })), "SCHEMA");
  assert.equal(rejected(event({ c: "ZZ" })), "SCHEMA");
  assert.equal(rejected(event({ c: "DROP TABLE" })), "SCHEMA");
  assert.equal(rejected(event({ r: 1 })), "SCHEMA");
});

test("agent and subject digests must be lowercase hex of exact width", () => {
  assert.equal(rejected(event({ a: "0123456789abcde" })), "SCHEMA");
  assert.equal(rejected(event({ a: "0123456789ABCDEF" })), "SCHEMA");
  assert.equal(rejected(event({ k: "f".repeat(31) })), "SCHEMA");
  assert.equal(rejected(event({ k: "f".repeat(33) })), "SCHEMA");
  assert.equal(rejected(event({ k: "--" + "f".repeat(30) })), "SCHEMA");
});

test("sequence and clock are integer-bounded; measurement is finite-bounded", () => {
  assert.equal(rejected(event({ s: 0 })), "SCHEMA");
  assert.equal(rejected(event({ s: -1 })), "SCHEMA");
  assert.equal(rejected(event({ s: 1.5 })), "SCHEMA");
  assert.equal(rejected(event({ s: 4_294_967_296 })), "SCHEMA");
  assert.equal(rejected(event({ t: -1 })), "SCHEMA");
  assert.equal(rejected(event({ t: "1700000000000" })), "SCHEMA");
  assert.equal(rejected(event({ m: 1_000_001 })), "SCHEMA");
  assert.equal(rejected(event({ m: -1_000_001 })), "SCHEMA");
  assert.equal(rejected(event({ m: "5" })), "SCHEMA");
  accepted(event({ m: 1_000_000 }));
  accepted(event({ m: -1_000_000 }));
});

test("the batch ceiling and the byte ceiling are both enforced before scoring", () => {
  const batch = Array.from({ length: LIMITS.batchMax + 1 }, (_unused, i) => event({ s: i + 1 }));
  assert.equal(rejected(batch), "SCHEMA");

  const fn = "x".repeat(LIMITS.bodyBytes + 1);
  const over = parseIngest(JSON.stringify({ padding: fn }));
  assert.equal(over.ok, false);
  if (!over.ok) assert.equal(over.code, "TOO_LARGE");
});

test("a batch at exactly the ceiling is still accepted", () => {
  const batch = Array.from({ length: LIMITS.batchMax }, (_unused, i) => event({ s: i + 1 }));
  const result = parseIngest(JSON.stringify(batch));
  assert.equal(result.ok, true);
  if (result.ok) assert.equal(result.events.length, LIMITS.batchMax);
});

/* ------------------------------------------------------------------ */
/*  Message authentication                                             */
/* ------------------------------------------------------------------ */

test("a valid MAC verifies; a tampered payload, wrong key or malformed MAC does not", () => {
  const registry = new AgentRegistry(Buffer.alloc(32, 7));
  const agent = registry.enroll("UMON");
  const e = accepted(event({ a: agent.id })) as IngestEvent;
  const message = `${e.v}|${e.a}|${e.s}|${e.t}|${e.r}|${e.c}|${e.m}|${e.k}`;
  const mac = signEvent(agent.key, message);

  assert.equal(verifyMac(agent.key, message, mac), true);
  assert.equal(verifyMac(agent.key, `${message}0`, mac), false, "appended byte must break the MAC");
  assert.equal(verifyMac(agent.key, message.replace("X7", "X8"), mac), false, "code swap must break the MAC");
  assert.equal(verifyMac(Buffer.alloc(32, 8), message, mac), false, "foreign key must not verify");
  assert.equal(verifyMac(agent.key, message, "zz"), false, "non-hex MAC must not verify");
  assert.equal(verifyMac(agent.key, message, mac.slice(0, 63)), false, "short MAC must not verify");
});

test("an agent cannot be impersonated by another role's enrolled key", () => {
  const registry = new AgentRegistry(Buffer.alloc(32, 3));
  const monitor = registry.enroll("UMON");
  const driver = registry.enroll("KMOD");
  assert.notEqual(monitor.id, driver.id);
  assert.equal(verifyMac(driver.key, "payload", signEvent(monitor.key, "payload")), false);
});

/* ------------------------------------------------------------------ */
/*  Velocity, replay, clock                                            */
/* ------------------------------------------------------------------ */

test("the token bucket admits a burst, refuses the excess, and refills over time", () => {
  const limiter = new Limiter();
  const now = 1_000_000;
  let admitted = 0;
  for (let i = 0; i < LIMITS.rateBurst + 50; i += 1) {
    if (limiter.take("agent-a", now, LIMITS.ratePerSec, LIMITS.rateBurst)) admitted += 1;
  }
  assert.equal(admitted, LIMITS.rateBurst, "burst ceiling must hold");

  // One second of refill buys exactly ratePerSec more slots.
  let afterRefill = 0;
  for (let i = 0; i < LIMITS.ratePerSec + 10; i += 1) {
    if (limiter.take("agent-a", now + 1000, LIMITS.ratePerSec, LIMITS.rateBurst)) afterRefill += 1;
  }
  assert.equal(afterRefill, LIMITS.ratePerSec);
});

test("a batch is charged for every sample it carries", () => {
  const limiter = new Limiter();
  const now = 5_000;
  assert.equal(limiter.take("a", now, 10, 10, 10), true);
  assert.equal(limiter.take("a", now, 10, 10, 1), false, "a full bucket spent in one batch leaves nothing");
});

test("one agent's flood cannot spend another agent's budget", () => {
  const limiter = new Limiter();
  for (let i = 0; i < 100; i += 1) limiter.take("flooder", 0, 10, 10);
  assert.equal(limiter.take("honest", 0, 10, 10), true);
});

test("sequence must be strictly increasing, and a forward jump is not a reset", () => {
  const limiter = new Limiter();
  assert.equal(limiter.admitSequence("a", 10, 0), "OK");
  assert.equal(limiter.admitSequence("a", 11, 1), "OK");
  assert.equal(limiter.admitSequence("a", 11, 2), "REPLAY", "equal sequence is a replay");
  assert.equal(limiter.admitSequence("a", 9, 3), "REPLAY", "lower sequence is a replay");
  assert.equal(limiter.admitSequence("a", 12, 4), "OK");
  assert.equal(limiter.admitSequence("a", 12 + 100_001, 5), "REPLAY", "teleporting counter is refused");
});

test("clock skew is bounded in both directions", () => {
  const now = 1_700_000_000_000;
  assert.equal(Limiter.skewVerdict(now, now), "OK");
  assert.equal(Limiter.skewVerdict(now - MAX_SKEW_MS, now), "OK");
  assert.equal(Limiter.skewVerdict(now - MAX_SKEW_MS - 1, now), "STALE");
  assert.equal(Limiter.skewVerdict(now + MAX_SKEW_MS + 1, now), "STALE");
});

/* ------------------------------------------------------------------ */
/*  Ledger                                                             */
/* ------------------------------------------------------------------ */

test("the ledger seals records and its chain verifies", () => {
  const ledger = new Ledger();
  const now = 1_700_000_000_000;
  ledger.append("BOOT", "-", "agents=3", now);
  ledger.append("VERDICT", "abcdef123456", "FLAGGED/CONVICT/0.95", now + 1);
  ledger.append("RELEASE", "abcdef123456", "PENDING/VETO", now + 2);

  assert.equal(ledger.length, 3);
  assert.equal(ledger.verify().ok, true);
  assert.equal(ledger.status().broken, false);

  const records = ledger.recordsView();
  assert.equal(records.length, 3);
  const [first, second, third] = records;
  assert.ok(first && second && third);
  assert.equal(second.prev, first.h, "each record must link to its predecessor");
  assert.equal(third.prev, second.h);
});

test("any edit to any field is detected, at the offending record and onwards", () => {
  const ledger = new Ledger();
  const now = 1_700_000_000_000;
  ledger.append("BOOT", "-", "agents=3", now);
  ledger.append("VERDICT", "abcdef123456", "FLAGGED/CONVICT/0.95", now + 1);
  ledger.append("VERDICT", "abcdef123456", "CLEAN/NONE/0.00", now + 2);

  const tampered = ledger.recordsView().map((r) => ({ ...r })) as Array<Record<string, unknown>>;
  const target = tampered[1];
  assert.ok(target);
  target["dt"] = "FLAGGED/CONVICT/0.99"; // inflate an old verdict

  const verdict = verifyRecords(tampered as never);
  assert.equal(verdict.ok, false);
  assert.equal(verdict.at, 2, "the first record whose hash no longer matches is named");
});

test("the chain is deterministic: identical history produces an identical head", () => {
  const a = new Ledger();
  const b = new Ledger();
  for (let i = 0; i < 5; i += 1) {
    a.append("VERDICT", "deadbeef0000", `FLAGGED/CONVICT/${i}`, 1000 + i);
    b.append("VERDICT", "deadbeef0000", `FLAGGED/CONVICT/${i}`, 1000 + i);
  }
  assert.equal(a.head, b.head);
  assert.equal(sealRecord(a.recordsView()[0]?.prev ?? "", 1, 1000, "VERDICT", "deadbeef0000", "FLAGGED/CONVICT/0"), a.recordsView()[0]?.h);
});
