/**
 * The conviction state machine. AUTHORITATIVE. SERVER-ONLY.
 *
 * Doctrine encoded here, in order of precedence:
 *
 *  1. CAPABILITY BEFORE ACCOUNT. A structural proof denies the capability at once
 *     (containment) while the subject's verdict stays PENDING. Block != Ban.
 *  2. CORROBORATION BEFORE CONVICTION. Two independent reporting rings, or one
 *     structural proof at certainty weight, sustained for `dwellMs`. Behavioural
 *     evidence from a single ring — including the arbiter's own aim model — can
 *     raise suspicion indefinitely and still never convict.
 *  3. CONVICTION IS STICKY. Decay clears suspicion but never un-flags a subject.
 *     Only an operator RELEASE, or an explicit operator FLAG, does that, and both
 *     are sealed into the hash-chained ledger.
 *
 * SUSPICION MODEL. Suspicion is the severity of the most severe unexpired sample in
 * the window, decayed while the subject is idle. It is deliberately not an average:
 * an averaging score lets benign noise issued *before* a hard proof dilute it, so a
 * mapped unsigned image would score lower than the proof it actually is. Nothing an
 * attacker does — flooding benign traffic first, for instance — can lower the peak.
 *
 * Memory is bounded at every level: per-subject sample window, subject table size,
 * latency window. Hostile input can cost CPU; it cannot cost unbounded heap.
 */
import {
  RING_BIT,
  type Disposition,
  type EvidenceCode,
  type GateId,
  type LadderStep,
  type PublicEvent,
  type PublicSubject,
  type RiskVerdict,
  type Role,
} from "../shared/protocol.ts";
import { CATALOG, CORROBORATE_SEV, STRUCTURAL_CERTAINTY_SEV } from "./catalog.ts";
import type { Ledger } from "./ledger.ts";

export const TUNING = {
  /** Evidence retention window. Samples older than this cannot corroborate. */
  windowMs: 60_000,
  /** Hard cap on retained samples per subject. */
  sampleCap: 512,
  /** Hard cap on tracked subjects. Least-recently-active non-flagged subjects evicted first. */
  subjectCap: 20_000,
  /**
   * Eviction is amortised: the table is allowed to overshoot the cap and is then
   * trimmed in one pass. Evicting a single entry per insert would make every
   * insertion scan the whole table once the cap is reached.
   */
  evictBatch: 1_000,
  /** Score at or above which the subject is a conviction candidate. */
  convictScore: 0.75,
  /** Score at or above which the subject is PENDING rather than CLEAN. */
  pendingScore: 0.35,
  /** Ladder thresholds, ascending. */
  suppressScore: 0.3,
  stripScore: 0.55,
  vetoScore: 0.7,
  /** Milliseconds the score must stay at or above `convictScore` before conviction. */
  dwellMs: 1_200,
  /** Idle time before suspicion starts decaying. */
  decayMs: 15_000,
  /** Fraction of the score removed per second of idleness once decay has begun. */
  decayPerSec: 0.12,
  /** Score below which a non-flagged subject returns to CLEAN. */
  clearScore: 0.1,
  /** Idle time after which a non-flagged subject is dropped from the table entirely. */
  subjectTtlMs: 600_000,
} as const;

type Sample = {
  readonly ts: number;
  readonly sev: number;
  readonly role: Role;
  readonly code: EvidenceCode;
  readonly structural: boolean;
};

type Subject = {
  readonly su: string;
  samples: Sample[];
  /** Severity of the most severe retained sample, decayed while idle. */
  peak: number;
  /** Corroborating sample count per role, kept in sync with eviction. */
  corroborating: Record<Role, number>;
  /** Lifetime sample count. */
  known: number;
  aboveSince: number | null;
  lastEvidence: number;
  /** Last time idle decay was applied, so elapsed time is charged only once. */
  lastDecayAt: number;
  verdict: RiskVerdict;
  step: LadderStep;
  contained: boolean;
  structuralProof: boolean;
  convictedAt: number | null;
};

export type CodeAggregate = { readonly c: EvidenceCode; readonly n: number; readonly max: number };

function popcount(mask: number): number {
  let n = mask;
  let count = 0;
  while (n !== 0) {
    count += n & 1;
    n >>= 1;
  }
  return count;
}

function clamp01(value: number): number {
  if (!Number.isFinite(value)) return 0;
  if (value < 0) return 0;
  if (value > 1) return 1;
  return value;
}

function round2(value: number): number {
  return Math.round(value * 100) / 100;
}

const STEP_ORDER: readonly LadderStep[] = ["NONE", "SUPPRESS", "STRIP", "VETO", "SHADOW", "CONVICT"];

function stepRank(step: LadderStep): number {
  const idx = STEP_ORDER.indexOf(step);
  return idx < 0 ? 0 : idx;
}

function targetStep(score: number, mask: number, flagged: boolean): LadderStep {
  if (flagged) return "CONVICT";
  if (popcount(mask) >= 2 && score >= TUNING.convictScore) return "SHADOW";
  if (score >= TUNING.vetoScore) return "VETO";
  if (score >= TUNING.stripScore) return "STRIP";
  if (score >= TUNING.suppressScore) return "SUPPRESS";
  return "NONE";
}

export type AdjudicationResult = {
  readonly event: PublicEvent;
  /** True when the verdict, ladder step or containment changed. */
  readonly transition: boolean;
};

export type ArbiterStats = {
  rx: number;
  drop: number;
  rej: number;
  rl: number;
  spf: number;
  sig: number;
  rpy: number;
  conv: number;
  subj: number;
  evicted: number;
};

export type GateStage = { readonly gate: GateId; readonly label: string; seen: number };

export type SubjectDetail = {
  readonly subject: PublicSubject;
  readonly codes: readonly CodeAggregate[];
  readonly roles: Readonly<Record<Role, number>>;
};

export class Arbiter {
  readonly #subjects = new Map<string, Subject>();
  readonly #ledger: Ledger;
  readonly gateStages: GateStage[] = [
    { gate: "G0", label: "SENSOR", seen: 0 },
    { gate: "G1", label: "SIGN-TRUST", seen: 0 },
    { gate: "G2", label: "CORPUS", seen: 0 },
    { gate: "G3", label: "BEHAVIOURAL", seen: 0 },
  ];

  readonly #roleCounts: Record<Role, number> = { UMON: 0, KMOD: 0, SRV: 0 };
  #seq = 0;
  #rx = 0;
  #drop = 0;
  #rej = 0;
  #rl = 0;
  #spf = 0;
  #sig = 0;
  #rpy = 0;
  #conv = 0;
  #evicted = 0;

  constructor(ledger: Ledger) {
    this.#ledger = ledger;
  }

  /* ---------------- counters ---------------- */

  countAccepted(): void {
    this.#rx += 1;
  }

  countRejected(kind: "rej" | "rl" | "spf" | "sig" | "rpy" | "drop"): void {
    if (kind === "rej") this.#rej += 1;
    else if (kind === "rl") this.#rl += 1;
    else if (kind === "spf") this.#spf += 1;
    else if (kind === "sig") this.#sig += 1;
    else if (kind === "rpy") this.#rpy += 1;
    else this.#drop += 1;
  }

  /* ---------------- adjudication ---------------- */

  /**
   * Fold one validated, authenticated sample into the state machine.
   * `agentTag` is derived from the authenticated principal, never echoed from the
   * payload. `measurement` is recorded for evidence completeness only: it never
   * enters the score, so inflating it buys an attacker nothing.
   */
  adjudicate(
    args: {
      readonly subjectDigest: string;
      readonly role: Role;
      readonly code: EvidenceCode;
      readonly measurement: number;
      readonly sourceClock: number;
      readonly agentTag: string;
    },
    now: number,
  ): AdjudicationResult {
    this.#seq += 1;
    const entry = CATALOG[args.code];
    const subject = this.#subject(args.subjectDigest, now);

    let disposition: Disposition;
    let retained = true;

    if (entry.cls === "BENIGN" && entry.sev === 0) {
      // Corpus allowlist hit: suppress the alert before it becomes a ticket, and
      // clear behavioural suspicion without diluting retained structural proofs.
      disposition = "SUPPRESS";
      retained = false;
      this.#expire(subject, now);
      if (!subject.structuralProof) subject.peak *= 0.5;
      subject.lastEvidence = now;
      subject.lastDecayAt = now;
    } else if (entry.cls === "BENIGN") {
      disposition = "ACCEPT";
    } else if (entry.cls === "STRUCTURAL") {
      disposition = "DENY";
    } else {
      disposition = "ESCALATE";
    }

    if (retained) {
      this.#retain(subject, {
        ts: now,
        sev: entry.sev,
        role: args.role,
        code: args.code,
        structural: entry.cls === "STRUCTURAL",
      });
    }

    const before = `${subject.verdict}:${subject.step}:${String(subject.contained)}`;
    this.#recompute(subject, now);
    const after = `${subject.verdict}:${subject.step}:${String(subject.contained)}`;
    const transition = before !== after;
    if (transition) this.#seal(subject, now);

    const stage = this.gateStages.find((s) => s.gate === entry.gate);
    if (stage !== undefined) stage.seen += 1;
    this.#roleCounts[args.role] += 1;

    const event: PublicEvent = {
      q: this.#seq,
      ts: now,
      ag: args.agentTag,
      role: args.role,
      su: subject.su,
      c: args.code,
      sev: entry.sev,
      gate: entry.gate,
      dsp: disposition === "ACCEPT" && subject.contained ? "CONTAIN" : disposition,
    };
    void args.measurement;
    void args.sourceClock;
    return { event, transition };
  }

  #subject(digest: string, now: number): Subject {
    const existing = this.#subjects.get(digest);
    if (existing !== undefined) return existing;
    const created: Subject = {
      su: digest.slice(0, 12),
      samples: [],
      peak: 0,
      corroborating: { UMON: 0, KMOD: 0, SRV: 0 },
      known: 0,
      aboveSince: null,
      lastEvidence: now,
      lastDecayAt: now,
      verdict: "CLEAN",
      step: "NONE",
      contained: false,
      structuralProof: false,
      convictedAt: null,
    };
    this.#subjects.set(digest, created);
    if (this.#subjects.size > TUNING.subjectCap) this.#trimSubjects();
    return created;
  }

  /**
   * One-pass trim. Flagged subjects are never evicted: a conviction outlives the
   * subject's activity, and quietly forgetting one would be the worst possible
   * failure mode for this component.
   */
  #trimSubjects(): void {
    const candidates: Array<{ key: string; last: number }> = [];
    for (const [key, sub] of this.#subjects) {
      if (sub.verdict === "FLAGGED") continue;
      candidates.push({ key, last: sub.lastEvidence });
    }
    candidates.sort((a, b) => a.last - b.last);
    const excess = this.#subjects.size - TUNING.subjectCap + TUNING.evictBatch;
    const limit = Math.min(candidates.length, Math.max(0, excess));
    for (let i = 0; i < limit; i += 1) {
      const victim = candidates[i];
      if (victim === undefined) break;
      this.#subjects.delete(victim.key);
      this.#evicted += 1;
    }
  }

  #retain(subject: Subject, sample: Sample): void {
    subject.samples.push(sample);
    subject.known += 1;
    subject.lastEvidence = sample.ts;
    subject.lastDecayAt = sample.ts;
    if (sample.sev > subject.peak) subject.peak = sample.sev;
    if (sample.sev >= CORROBORATE_SEV) subject.corroborating[sample.role] += 1;
    if (sample.structural && sample.sev >= STRUCTURAL_CERTAINTY_SEV) subject.structuralProof = true;

    // Bounded retention: a subject can never accumulate more than sampleCap samples,
    // and nothing older than the corroboration window may keep a ring's bit set.
    while (subject.samples.length > TUNING.sampleCap) this.#evictOldest(subject);

    const cutoff = sample.ts - TUNING.windowMs;
    let droppedProof = false;
    for (;;) {
      const [head] = subject.samples;
      if (head === undefined || head.ts > cutoff) break;
      if (head.structural && head.sev >= STRUCTURAL_CERTAINTY_SEV) droppedProof = true;
      this.#evictOldest(subject);
    }
    if (droppedProof) this.#recheckStructuralProof(subject);
  }

  #evictOldest(subject: Subject): void {
    const evicted = subject.samples.shift();
    if (evicted === undefined) return;
    if (evicted.structural && evicted.sev >= STRUCTURAL_CERTAINTY_SEV) {
      this.#recheckStructuralProof(subject);
    }
    if (evicted.sev >= CORROBORATE_SEV) {
      subject.corroborating[evicted.role] = Math.max(0, subject.corroborating[evicted.role] - 1);
    }
    // Only the departing sample can invalidate the peak, so this rescan is rare.
    if (evicted.sev >= subject.peak - 1e-9) {
      let peak = 0;
      for (const s of subject.samples) if (s.sev > peak) peak = s.sev;
      subject.peak = peak;
    }
  }

  /**
   * Drop samples that have left the corroboration window.
   *
   * Without this, stale evidence would keep lending credit to fresh signals: a
   * corpus hit from ten minutes ago would still satisfy the two-ring requirement
   * for a behavioural sample arriving now, which is precisely the false-positive
   * pathway this component exists to close.
   */
  #expire(subject: Subject, now: number): void {
    const cutoff = now - TUNING.windowMs;
    let lostProof = false;
    for (;;) {
      const [head] = subject.samples;
      if (head === undefined || head.ts > cutoff) break;
      if (head.structural && head.sev >= STRUCTURAL_CERTAINTY_SEV) lostProof = true;
      this.#evictOldest(subject);
    }
    if (lostProof) this.#recheckStructuralProof(subject);
  }

  #recheckStructuralProof(subject: Subject): void {
    for (const s of subject.samples) {
      if (s.structural && s.sev >= STRUCTURAL_CERTAINTY_SEV) {
        subject.structuralProof = true;
        return;
      }
    }
    subject.structuralProof = false;
  }

  #mask(subject: Subject): number {
    let mask = 0;
    if (subject.corroborating.KMOD > 0) mask |= RING_BIT.KMOD;
    if (subject.corroborating.UMON > 0) mask |= RING_BIT.UMON;
    if (subject.corroborating.SRV > 0) mask |= RING_BIT.SRV;
    return mask;
  }

  #score(subject: Subject): number {
    return clamp01(subject.peak / 100);
  }

  /**
   * Re-derive verdict, ladder and containment. Called on every sample and on every
   * sweep, so a dwell requirement matures on wall-clock time rather than waiting for
   * the next sample.
   */
  #recompute(subject: Subject, now: number): void {
    const score = this.#score(subject);
    const mask = this.#mask(subject);

    if (score >= TUNING.convictScore) {
      if (subject.aboveSince === null) subject.aboveSince = now;
    } else {
      subject.aboveSince = null;
    }
    const dwell = subject.aboveSince === null ? 0 : now - subject.aboveSince;

    // Two independent rings, or a single structural proof at certainty weight.
    const corroborated = popcount(mask) >= 2;
    const canConvict = corroborated || subject.structuralProof;

    if (subject.verdict !== "FLAGGED" && canConvict && dwell >= TUNING.dwellMs) {
      subject.verdict = "FLAGGED";
      subject.convictedAt = now;
      this.#conv += 1;
    } else if (subject.verdict === "CLEAN" && score >= TUNING.pendingScore) {
      subject.verdict = "PENDING";
    } else if (subject.verdict === "PENDING" && score < TUNING.clearScore && mask === 0) {
      subject.verdict = "CLEAN";
    }

    if (subject.verdict === "FLAGGED") {
      subject.step = "CONVICT";
    } else {
      const target = targetStep(score, mask, false);
      // The ladder only ever advances within an episode; it is lowered by release
      // or by decay back to CLEAN, never by a quiet score wobble.
      subject.step = stepRank(target) > stepRank(subject.step) ? target : subject.step;
      if (subject.verdict === "CLEAN" && score < TUNING.clearScore) subject.step = "NONE";
    }

    // Containment is capability-scoped, reversible and independent of the verdict:
    // it is the ladder's STRIP step and above, plus any structural proof. A player
    // can be contained, silently, while their account is never touched.
    subject.contained =
      subject.verdict === "FLAGGED" ||
      subject.structuralProof ||
      stepRank(subject.step) >= stepRank("STRIP");
  }

  #seal(subject: Subject, now: number): void {
    this.#ledger.append(
      subject.verdict === "FLAGGED" ? "VERDICT" : "CONTAIN",
      subject.su,
      `${subject.verdict}/${subject.step}/${round2(this.#score(subject)).toFixed(2)}`,
      now,
    );
  }

  /* ---------------- operator actions ---------------- */

  release(tag: string, now: number): boolean {
    const target = this.#find(tag);
    if (target === null) return false;
    const was = `${target.verdict}/${target.step}`;
    target.verdict = "CLEAN";
    target.step = "NONE";
    target.contained = false;
    target.peak = 0;
    target.samples = [];
    target.corroborating = { UMON: 0, KMOD: 0, SRV: 0 };
    target.structuralProof = false;
    target.convictedAt = null;
    target.aboveSince = null;
    this.#ledger.append("RELEASE", target.su, was, now);
    return true;
  }

  forceFlag(tag: string, now: number): boolean {
    const target = this.#find(tag);
    if (target === null) return false;
    target.verdict = "FLAGGED";
    target.step = "CONVICT";
    target.contained = true;
    target.convictedAt = now;
    this.#conv += 1;
    this.#ledger.append("VERDICT", target.su, "FLAGGED/CONVICT/operator", now);
    return true;
  }

  #find(tag: string): Subject | null {
    const direct = this.#subjects.get(tag);
    if (direct !== undefined) return direct;
    const needle = tag.slice(0, 12);
    for (const sub of this.#subjects.values()) {
      if (sub.su === needle) return sub;
    }
    return null;
  }

  /* ---------------- decay + housekeeping ---------------- */

  /**
   * Snapshot-tick sweep: mature any pending dwell requirement, decay idle suspicion,
   * expire stale subjects. Returns the number of subjects whose state changed.
   */
  sweep(now: number): number {
    let changed = 0;
    for (const [key, subject] of this.#subjects) {
      const idle = now - subject.lastEvidence;
      if (idle > TUNING.subjectTtlMs && subject.verdict !== "FLAGGED") {
        this.#subjects.delete(key);
        continue;
      }
      this.#expire(subject, now);
      if (idle > TUNING.decayMs) {
        // Time-proportional, not per-call: the decay applied must not depend on how
        // often the sweeper happens to run.
        const decayFrom = Math.max(subject.lastDecayAt, subject.lastEvidence + TUNING.decayMs);
        const elapsed = Math.max(0, now - decayFrom);
        const factor = (1 - TUNING.decayPerSec) ** (elapsed / 1000);
        subject.peak *= factor;
        subject.lastDecayAt = Math.max(subject.lastDecayAt, now);
      }
      const before = `${subject.verdict}:${subject.step}:${String(subject.contained)}`;
      this.#recompute(subject, now);
      const after = `${subject.verdict}:${subject.step}:${String(subject.contained)}`;
      if (before !== after) {
        changed += 1;
        this.#seal(subject, now);
      }
    }
    return changed;
  }

  /* ---------------- read models ---------------- */

  snapshot(now: number, limit: number): PublicSubject[] {
    const out: PublicSubject[] = [];
    for (const subject of this.#subjects.values()) {
      out.push({
        su: subject.su,
        vd: subject.verdict,
        rm: this.#mask(subject),
        sc: round2(this.#score(subject)),
        dw: subject.aboveSince === null ? 0 : now - subject.aboveSince,
        st: subject.step,
        ct: subject.contained,
        n: subject.samples.length,
        last: subject.lastEvidence,
      });
    }
    out.sort((a, b) => b.sc - a.sc || b.last - a.last);
    return out.slice(0, limit);
  }

  /** Per-subject evidence breakdown for the operator console's detail pane. */
  detail(tag: string, now: number): SubjectDetail | null {
    const target = this.#find(tag);
    if (target === null) return null;
    const agg = new Map<EvidenceCode, { n: number; max: number }>();
    const roles: Record<Role, number> = { UMON: 0, KMOD: 0, SRV: 0 };
    for (const s of target.samples) {
      const cur = agg.get(s.code);
      if (cur === undefined) agg.set(s.code, { n: 1, max: s.sev });
      else {
        cur.n += 1;
        if (s.sev > cur.max) cur.max = s.sev;
      }
      roles[s.role] += 1;
    }
    const codes: CodeAggregate[] = Array.from(agg.entries())
      .map(([c, v]) => ({ c, n: v.n, max: v.max }))
      .sort((a, b) => b.n - a.n);
    return {
      subject: {
        su: target.su,
        vd: target.verdict,
        rm: this.#mask(target),
        sc: round2(this.#score(target)),
        dw: target.aboveSince === null ? 0 : now - target.aboveSince,
        st: target.step,
        ct: target.contained,
        n: target.samples.length,
        last: target.lastEvidence,
      },
      codes,
      roles,
    };
  }

  stats(): ArbiterStats {
    return {
      rx: this.#rx,
      drop: this.#drop,
      rej: this.#rej,
      rl: this.#rl,
      spf: this.#spf,
      sig: this.#sig,
      rpy: this.#rpy,
      conv: this.#conv,
      subj: this.#subjects.size,
      evicted: this.#evicted,
    };
  }

  get sequence(): number {
    return this.#seq;
  }

  /** Adjudicated sample counts per reporting ring. */
  roleCounts(): Record<Role, number> {
    return { UMON: this.#roleCounts.UMON, KMOD: this.#roleCounts.KMOD, SRV: this.#roleCounts.SRV };
  }

  /** Subjects above a suspicion floor, used by the sweeper to decide activity. */
  get activeSubjects(): number {
    let active = 0;
    for (const s of this.#subjects.values()) if (s.verdict !== "CLEAN") active += 1;
    return active;
  }
}
