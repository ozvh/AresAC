/**
 * Input-velocity and replay defence.
 *
 * Three independent gates, each cheap enough to run on every sample:
 *   1. token bucket per agent — a flood cannot buy adjudication slots
 *   2. strictly monotonic per-agent sequence — a captured frame cannot be replayed,
 *      and a forged "reset to 1" cannot resurrect an expired counter
 *   3. clock-skew window — a drifted or backdated sender clock is refused rather
 *      than trusted; the arbiter's own clock is the only ordering authority
 *
 * All state is keyed by authenticated agent id, so no client-supplied value can
 * widen an attacker's budget. Buckets are pruned on a timer so a fleet-wide id
 * spray cannot exhaust memory.
 */
/** Maximum tolerated difference between sender clock and arbiter clock. */
export const MAX_SKEW_MS = 300_000;

/** Largest accepted jump in an agent's sequence counter before it is treated as a reset attack. */
const MAX_SEQ_GAP = 100_000;

/** Idle lifetime for per-agent counters. */
const IDLE_TTL_MS = 300_000;

type Bucket = { tokens: number; last: number };
type SeqState = { max: number; seen: number };

export type VelocityVerdict = "OK" | "RATE" | "REPLAY" | "STALE";

export class Limiter {
  readonly #buckets = new Map<string, Bucket>();
  readonly #seq = new Map<string, SeqState>();

  /**
   * Spend `cost` tokens for `id`. Returns false when the bucket cannot cover the
   * whole cost, in which case nothing is spent: a request is never half-admitted.
   * Refill is continuous rather than tick-based, so a burst that straddles a
   * window boundary cannot be double-spent.
   */
  take(id: string, now: number, perSec: number, burst: number, cost = 1): boolean {
    const charge = Math.min(Math.max(1, cost), burst);
    const existing = this.#buckets.get(id);
    if (existing === undefined) {
      this.#buckets.set(id, { tokens: burst - charge, last: now });
      return true;
    }
    const elapsed = Math.max(0, now - existing.last);
    const refilled = Math.min(burst, existing.tokens + (elapsed * perSec) / 1000);
    if (refilled < charge) {
      existing.tokens = refilled;
      existing.last = now;
      return false;
    }
    existing.tokens = refilled - charge;
    existing.last = now;
    return true;
  }

  /**
   * Admit only a strictly increasing sequence per agent. The first observation
   * establishes the floor: a replayed enrolment frame from a different session
   * cannot lower it again.
   */
  admitSequence(id: string, seq: number, now: number): VelocityVerdict {
    const state = this.#seq.get(id);
    if (state === undefined) {
      this.#seq.set(id, { max: seq, seen: now });
      return "OK";
    }
    if (seq <= state.max) {
      state.seen = now;
      return "REPLAY";
    }
    if (seq - state.max > MAX_SEQ_GAP) {
      // A counter that teleports forward is a counter under third-party control.
      state.seen = now;
      return "REPLAY";
    }
    state.max = seq;
    state.seen = now;
    return "OK";
  }

  static skewVerdict(senderClock: number, now: number): VelocityVerdict {
    return Math.abs(now - senderClock) > MAX_SKEW_MS ? "STALE" : "OK";
  }

  /** Bounded housekeeping. Called on the snapshot sweep. */
  prune(now: number): number {
    let removed = 0;
    for (const [id, bucket] of this.#buckets) {
      if (now - bucket.last > IDLE_TTL_MS) {
        this.#buckets.delete(id);
        removed += 1;
      }
    }
    for (const [id, state] of this.#seq) {
      if (now - state.seen > IDLE_TTL_MS) {
        this.#seq.delete(id);
        removed += 1;
      }
    }
    return removed;
  }

  get trackedAgents(): number {
    return this.#seq.size;
  }
}

/**
 * Fixed-capacity ring of adjudication latencies used for the p95 readout.
 *
 * Stored in MICROSECONDS. Adjudication of a single sample is routinely sub-millisecond,
 * so millisecond resolution would report a flat zero for the very property this
 * component exists to demonstrate. Allocation-free on the hot path: one Int32Array,
 * recycled forever.
 */
export class LatencyWindow {
  readonly #samples: Int32Array;
  #cursor = 0;
  #filled = 0;

  constructor(capacity: number) {
    this.#samples = new Int32Array(capacity);
  }

  /** `value` is milliseconds. */
  push(value: number): void {
    const micros = Math.round(value * 1000);
    const clamped = Math.max(0, Math.min(2_147_483_647, micros));
    this.#samples[this.#cursor] = clamped;
    this.#cursor = (this.#cursor + 1) % this.#samples.length;
    if (this.#filled < this.#samples.length) this.#filled += 1;
  }

  /** p95 in microseconds. */
  p95(): number {
    if (this.#filled === 0) return 0;
    const view = this.#samples.subarray(0, this.#filled);
    const sorted = Array.from(view).sort((a, b) => a - b);
    const idx = Math.min(sorted.length - 1, Math.floor(sorted.length * 0.95));
    return sorted[idx] ?? 0;
  }

  get count(): number {
    return this.#filled;
  }
}
