/**
 * Doctrine tests. These are the falsifiable claims this component makes about its
 * own behaviour, written as the cases that would embarrass it:
 *
 *   - behavioural evidence from any single ring can never convict, no matter how
 *     far above the conviction score it climbs
 *   - capability is denied before the account is touched
 *   - a conviction is sticky, and only an operator can clear it
 *   - stale evidence cannot corroborate fresh evidence
 *
 * Time is driven explicitly, so every result here is deterministic.
 */
import assert from "node:assert/strict";
import { test } from "node:test";
import type { EvidenceCode, PublicSubject, Role } from "../shared/protocol.ts";
import { Ledger } from "../server/ledger.ts";
import { Arbiter, TUNING } from "../server/machine.ts";

const T0 = 1_700_000_000_000;

function digest(n: number): string {
  return n.toString(16).padStart(2, "0").repeat(16);
}

type Rig = { arb: Arbiter; ledger: Ledger };

function rig(): Rig {
  const ledger = new Ledger();
  return { arb: new Arbiter(ledger), ledger };
}

function feed(
  arb: Arbiter,
  args: { digest: string; role: Role; code: EvidenceCode; start?: number; count: number; gapMs: number },
): number {
  const start = args.start ?? T0;
  let now = start;
  for (let i = 0; i < args.count; i += 1) {
    arb.adjudicate(
      {
        subjectDigest: args.digest,
        role: args.role,
        code: args.code,
        measurement: 1,
        sourceClock: now,
        agentTag: "agenttag",
      },
      now,
    );
    now += args.gapMs;
  }
  return now;
}

function read(arb: Arbiter, n: number, now: number): PublicSubject {
  const found = arb.snapshot(now, 1000).find((s) => s.su === digest(n).slice(0, 12));
  assert.ok(found, `subject ${n} should be tracked`);
  return found;
}

/* ------------------------------------------------------------------ */
/*  Benign traffic must stay benign                                    */
/* ------------------------------------------------------------------ */

test("signed overlay traffic never leaves CLEAN and is never contained", () => {
  const { arb } = rig();
  const end = feed(arb, { digest: digest(1), role: "UMON", code: "XB", count: 200, gapMs: 100 });
  arb.sweep(end);
  const s = read(arb, 1, end);
  assert.equal(s.vd, "CLEAN");
  assert.equal(s.st, "NONE");
  assert.equal(s.ct, false);
  assert.equal(s.rm, 0, "a benign sample must not corroborate its ring");
  assert.ok(s.sc < TUNING.pendingScore);
});

test("allowlist hits suppress rather than escalate, and grow the corpus path", () => {
  const { arb } = rig();
  const end = feed(arb, { digest: digest(2), role: "SRV", code: "XD", count: 100, gapMs: 50 });
  arb.sweep(end);
  const s = read(arb, 2, end);
  assert.equal(s.vd, "CLEAN");
  assert.equal(s.ct, false);
  assert.equal(s.sc, 0);
});

/* ------------------------------------------------------------------ */
/*  No single ring may convict on behavioural evidence                 */
/* ------------------------------------------------------------------ */

test("a user-mode behavioural signal alone never convicts", () => {
  const { arb } = rig();
  const end = feed(arb, { digest: digest(3), role: "UMON", code: "X4", count: 400, gapMs: 75 });
  arb.sweep(end);
  arb.sweep(end + 60_000);
  const s = read(arb, 3, end + 60_000);
  assert.notEqual(s.vd, "FLAGGED", "debug-object evidence alone must not convict");
});

test("the external arbiter's own behavioural model alone never convicts, even above the conviction score", () => {
  const { arb } = rig();
  const end = feed(arb, { digest: digest(4), role: "SRV", code: "X8", count: 600, gapMs: 60 });
  arb.sweep(end);
  const s = read(arb, 4, end);
  assert.ok(s.sc >= TUNING.convictScore, `score ${s.sc} should exceed the conviction score`);
  assert.equal(s.vd, "PENDING", "suspicion may be permanent; a conviction may not");
  assert.equal(s.ct, true, "the capability is still denied");
  assert.equal(s.rm, 4, "only the external ring corroborates");
});

test("a corpus hit or foreign-thread signal alone is strong but not sufficient", () => {
  for (const [code, role] of [
    ["X6", "KMOD"],
    ["X5", "KMOD"],
    ["XC", "KMOD"],
  ] as ReadonlyArray<[EvidenceCode, Role]>) {
    const { arb } = rig();
    const end = feed(arb, { digest: digest(5), role, code, count: 200, gapMs: 50 });
    arb.sweep(end);
    const s = read(arb, 5, end);
    assert.equal(s.vd, "PENDING", `${code} from ${role} alone must not convict`);
    assert.ok(s.sc >= TUNING.convictScore, `${code} should still score highly`);
  }
});

/* ------------------------------------------------------------------ */
/*  The two paths to conviction                                        */
/* ------------------------------------------------------------------ */

test("a structural proof convicts from a single ring once the dwell requirement matures", () => {
  const { arb, ledger } = rig();
  const t = feed(arb, { digest: digest(6), role: "UMON", code: "X1", count: 1, gapMs: 0 });

  const early = read(arb, 6, t);
  assert.equal(early.vd, "PENDING", "already high suspicion, but not yet a conviction");
  assert.equal(early.ct, true, "the capability is denied immediately");
  assert.equal(early.st, "VETO", "the ladder climbs to veto, but not to conviction, yet");

  arb.sweep(t + TUNING.dwellMs + 100);
  const matured = read(arb, 6, t + TUNING.dwellMs + 100);
  assert.equal(matured.vd, "FLAGGED");
  assert.equal(matured.st, "CONVICT");
  assert.equal(ledger.verify().ok, true);
  assert.ok(ledger.length > 0, "the transition must be sealed");
});

test("two independent rings convict even when neither signal is individually certain", () => {
  const { arb } = rig();
  let t = feed(arb, { digest: digest(7), role: "KMOD", code: "X5", start: T0, count: 1, gapMs: 0 });
  t = feed(arb, { digest: digest(7), role: "UMON", code: "X6", start: t, count: 1, gapMs: 0 });
  arb.sweep(t + TUNING.dwellMs + 100);
  const s = read(arb, 7, t + TUNING.dwellMs + 100);
  assert.equal(s.rm, 3, "both rings must be recorded as corroborating");
  assert.equal(s.vd, "FLAGGED");
});

test("the dwell requirement is real: suspicion must be sustained, not merely touched", () => {
  const { arb } = rig();
  const t = feed(arb, { digest: digest(8), role: "UMON", code: "X3", count: 1, gapMs: 0 });
  arb.sweep(t + TUNING.dwellMs - 200);
  assert.equal(read(arb, 8, t + TUNING.dwellMs - 200).vd, "PENDING");
  arb.sweep(t + TUNING.dwellMs + 50);
  assert.equal(read(arb, 8, t + TUNING.dwellMs + 50).vd, "FLAGGED");
});

/* ------------------------------------------------------------------ */
/*  Sticky conviction, operator authority                              */
/* ------------------------------------------------------------------ */

test("a conviction survives an hour of decay", () => {
  const { arb } = rig();
  const t = feed(arb, { digest: digest(9), role: "UMON", code: "X2", count: 1, gapMs: 0 });
  arb.sweep(t + TUNING.dwellMs + 100);
  assert.equal(read(arb, 9, t + 200).vd, "FLAGGED");
  for (let i = 1; i <= 120; i += 1) arb.sweep(t + i * 30_000);
  const s = read(arb, 9, t + 120 * 30_000);
  assert.equal(s.vd, "FLAGGED", "decay clears suspicion, never a conviction");
  assert.ok(s.sc < TUNING.convictScore, "the underlying score does decay");
});

test("only an operator release clears a conviction, and it is sealed", () => {
  const { arb, ledger } = rig();
  const t = feed(arb, { digest: digest(10), role: "KMOD", code: "X2", count: 1, gapMs: 0 });
  arb.sweep(t + TUNING.dwellMs + 100);
  assert.equal(read(arb, 10, t).vd, "FLAGGED");

  const tag = digest(10).slice(0, 12);
  assert.equal(arb.release(tag, t + 10_000), true);
  const released = read(arb, 10, t + 10_000);
  assert.equal(released.vd, "CLEAN");
  assert.equal(released.st, "NONE");
  assert.equal(released.ct, false);
  assert.equal(released.rm, 0);
  assert.equal(arb.release("ffffffffffff", t), false, "an unknown subject is not a silent success");
  assert.ok(ledger.tail(10).some((r) => r.kind === "RELEASE"));
});

test("an operator can convict directly, and that too is sealed", () => {
  const { arb, ledger } = rig();
  feed(arb, { digest: digest(11), role: "UMON", code: "X7", count: 1, gapMs: 0 });
  assert.equal(arb.forceFlag(digest(11).slice(0, 12), T0), true);
  assert.equal(read(arb, 11, T0).vd, "FLAGGED");
  assert.ok(ledger.tail(10).some((r) => r.kind === "VERDICT" && r.dt.includes("operator")));
});

/* ------------------------------------------------------------------ */
/*  Suppression and expiry                                             */
/* ------------------------------------------------------------------ */

test("an allowlist hit clears behavioural suspicion", () => {
  const { arb } = rig();
  let t = feed(arb, { digest: digest(12), role: "UMON", code: "X7", count: 1, gapMs: 0 });
  assert.equal(read(arb, 12, t).vd, "PENDING");
  t = feed(arb, { digest: digest(12), role: "UMON", code: "XD", start: t, count: 8, gapMs: 10 });
  const s = read(arb, 12, t);
  assert.equal(s.vd, "CLEAN");
  assert.equal(s.st, "NONE");
});

test("an allowlist hit does not erase a structural proof of tampering", () => {
  const { arb } = rig();
  let t = feed(arb, { digest: digest(13), role: "UMON", code: "X1", count: 1, gapMs: 0 });
  t = feed(arb, { digest: digest(13), role: "UMON", code: "XD", start: t, count: 40, gapMs: 20 });
  const s = read(arb, 13, t);
  assert.equal(s.ct, true, "an allowlisted binary does not retroactively un-map an unsigned image");
  assert.equal(s.sc, 0.9, "allowlist traffic must not dilute structural certainty");
  arb.sweep(T0 + TUNING.dwellMs);
  assert.equal(read(arb, 13, T0 + TUNING.dwellMs).vd, "FLAGGED");
});

test("stale evidence cannot corroborate fresh evidence", () => {
  const { arb } = rig();
  // A kernel-side corpus hit establishes corroboration...
  const t1 = feed(arb, { digest: digest(14), role: "KMOD", code: "X6", count: 1, gapMs: 0 });
  assert.equal(read(arb, 14, t1).rm, 1);

  // ...then a full window elapses with no further kernel evidence.
  const later = t1 + TUNING.windowMs + 5_000;
  arb.sweep(later);
  assert.equal(read(arb, 14, later).rm, 0, "expired evidence must stop corroborating");

  // A fresh behavioural sample from another ring must not now inherit two-ring credit.
  let t2 = feed(arb, { digest: digest(14), role: "SRV", code: "X8", start: later, count: 200, gapMs: 60 });
  t2 = t2 + TUNING.dwellMs + 100;
  arb.sweep(t2);
  const s = read(arb, 14, t2);
  assert.equal(s.rm, 4, "only the fresh ring corroborates");
  assert.notEqual(s.vd, "FLAGGED");
});

test("containment is reversible when the evidence leaves the window", () => {
  const { arb } = rig();
  const t = feed(arb, { digest: digest(15), role: "KMOD", code: "X5", count: 1, gapMs: 0 });
  assert.equal(read(arb, 15, t).ct, true);
  const later = t + TUNING.windowMs + TUNING.decayMs + 1_000;
  arb.sweep(later);
  const s = read(arb, 15, later);
  assert.equal(s.rm, 0);
  assert.equal(s.vd, "CLEAN");
  assert.equal(s.ct, false, "a capability denial must not outlive its evidence");
});

/* ------------------------------------------------------------------ */
/*  Bounded state                                                      */
/* ------------------------------------------------------------------ */

test("the subject table stays bounded under a hostile id spray", () => {
  const { arb } = rig();
  const total = TUNING.subjectCap + 2_000;
  for (let i = 0; i < total; i += 1) {
    arb.adjudicate(
      {
        subjectDigest: i.toString(16).padStart(32, "0"),
        role: "UMON",
        code: "XB",
        measurement: 0,
        sourceClock: T0,
        agentTag: "spray",
      },
      T0,
    );
  }
  const all = arb.snapshot(T0, total + 10);
  assert.ok(all.length <= TUNING.subjectCap, `table held ${all.length}, cap is ${TUNING.subjectCap}`);
  assert.ok(arb.stats().evicted > 0, "evictions must be counted, not hidden");
});

test("a subject's retained samples are capped", () => {
  const { arb } = rig();
  const end = feed(arb, { digest: digest(16), role: "UMON", code: "X4", count: TUNING.sampleCap + 300, gapMs: 1 });
  const s = read(arb, 16, end);
  assert.ok(s.n <= TUNING.sampleCap, `retained ${s.n} samples, cap is ${TUNING.sampleCap}`);
});

test("sample-cap eviction removes the last structural proof's conviction authority", () => {
  const { arb } = rig();
  feed(arb, { digest: digest(17), role: "UMON", code: "X1", count: 1, gapMs: 0 });
  feed(arb, { digest: digest(17), role: "UMON", code: "XB", start: T0 + 1, count: TUNING.sampleCap, gapMs: 0 });
  feed(arb, { digest: digest(17), role: "SRV", code: "X8", start: T0 + 2, count: 1, gapMs: 0 });
  const later = T0 + 2 + TUNING.dwellMs;
  arb.sweep(later);
  const s = read(arb, 17, later);
  assert.equal(s.rm, 4);
  assert.equal(s.sc, 0.8);
  assert.equal(s.vd, "PENDING", "an evicted proof cannot authorize single-ring conviction");
});

test("sample-cap eviction preserves conviction authority when another structural proof remains", () => {
  const { arb } = rig();
  feed(arb, { digest: digest(18), role: "UMON", code: "X1", count: 2, gapMs: 1 });
  feed(arb, { digest: digest(18), role: "UMON", code: "XB", start: T0 + 2, count: TUNING.sampleCap - 1, gapMs: 0 });
  arb.sweep(T0 + TUNING.dwellMs);
  assert.equal(read(arb, 18, T0 + TUNING.dwellMs).vd, "FLAGGED");
});

test("idle decay depends on elapsed time, not sweep cadence or repeated timestamps", () => {
  const single = rig().arb;
  const frequent = rig().arb;
  for (const arb of [single, frequent]) {
    feed(arb, { digest: digest(19), role: "SRV", code: "X8", count: 1, gapMs: 0 });
  }
  const end = T0 + TUNING.decayMs + 5_000;
  single.sweep(end);
  for (let now = T0 + TUNING.decayMs; now <= end; now += 500) frequent.sweep(now);
  const expected = Math.round(0.8 * Math.pow(1 - TUNING.decayPerSec, 5) * 100) / 100;
  assert.equal(read(single, 19, end).sc, expected);
  assert.equal(read(frequent, 19, end).sc, expected);
  frequent.sweep(end);
  assert.equal(read(frequent, 19, end).sc, expected);
  feed(frequent, { digest: digest(19), role: "SRV", code: "X8", start: end, count: 1, gapMs: 0 });
  frequent.sweep(end + TUNING.decayMs);
  assert.equal(read(frequent, 19, end + TUNING.decayMs).sc, 0.8);
  frequent.sweep(end + TUNING.decayMs + 5_000);
  assert.equal(read(frequent, 19, end + TUNING.decayMs + 5_000).sc, expected);
});
