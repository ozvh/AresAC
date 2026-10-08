/**
 * Runtime composition root.
 *
 * Owns the mutable control state (pause, rate, scenario, operator token), the
 * five-second telemetry windows, and the snapshot tick that publishes state to
 * observers. Transport lives in http.ts; this file knows nothing about sockets.
 */
import { LIMITS, type PublicCounters, type PublicEvent, type PublicTuning, type SnapshotResponse } from "../shared/protocol.ts";
import type { AgentRegistry } from "./agents.ts";
import type { Fleet } from "./fleet.ts";
import type { Ledger } from "./ledger.ts";
import { LatencyWindow, Limiter, MAX_SKEW_MS } from "./limiter.ts";
import { CORROBORATE_SEV, STRUCTURAL_CERTAINTY_SEV } from "./catalog.ts";
import type { Auth } from "./auth.ts";
import type { Store } from "./db.ts";
import { Arbiter, TUNING } from "./machine.ts";
import type { RequestIntake } from "./requests.ts";
import type { Broadcaster } from "./sse.ts";
import type { Subscriptions } from "./subscriptions.ts";
import type { UploadService } from "./uploads.ts";

/** Snapshot cadence. Frames are also pushed immediately on transition. */
const SNAPSHOT_MS = 500;

/**
 * Housekeeping cadence for the slow sweeps: session pruning, subscription expiry,
 * renewal notices and upload retention. A minute is right for all four — the fastest
 * thing among them is a renewal notice, and a notice that is a minute late is a notice
 * that is a minute early by the only measure that matters.
 */
const HOUSEKEEP_MS = 60_000;

/** Subjects carried in a snapshot frame. The console virtualises what it has; this caps the wire. */
const SNAPSHOT_SUBJECTS = 120;

type TpsSample = { t: number; rx: number };

export class Runtime {
  readonly arbiter: Arbiter;
  readonly ledger: Ledger;
  readonly limiter = new Limiter();
  readonly latency = new LatencyWindow(4096);
  readonly bus: Broadcaster;
  readonly registry: AgentRegistry;
  readonly fleet: Fleet;
  readonly requests: RequestIntake;
  readonly auth: Auth;
  readonly store: Store;
  readonly subs: Subscriptions;
  readonly uploads: UploadService;
  readonly operatorToken: string;
  readonly bootedAt = Date.now();
  readonly bootIso: string;

  #paused = false;
  #corpus = 29_411;
  #tpsSamples: TpsSample[] = [];
  #snapshotTimer: NodeJS.Timeout | null = null;
  #housekeepTimer: NodeJS.Timeout | null = null;
  /** Guards against a slow relay stacking housekeeping passes on top of each other. */
  #housekeeping = false;
  #lastPublish = 0;

  constructor(args: {
    arbiter: Arbiter;
    ledger: Ledger;
    bus: Broadcaster;
    registry: AgentRegistry;
    fleet: Fleet;
    requests: RequestIntake;
    auth: Auth;
    store: Store;
    subs: Subscriptions;
    uploads: UploadService;
    operatorToken: string;
  }) {
    this.arbiter = args.arbiter;
    this.ledger = args.ledger;
    this.bus = args.bus;
    this.registry = args.registry;
    this.fleet = args.fleet;
    this.requests = args.requests;
    this.auth = args.auth;
    this.store = args.store;
    this.subs = args.subs;
    this.uploads = args.uploads;
    this.operatorToken = args.operatorToken;
    this.bootIso = new Date(this.bootedAt).toISOString();
  }

  start(): void {
    this.bus.start();
    this.ledger.append("BOOT", "-", `agents=${this.registry.size}`, Date.now());
    this.#snapshotTimer = setInterval(() => this.#tick(), SNAPSHOT_MS);
    // The listener holds the event loop open; this timer must not keep a shutting
    // down process alive.
    this.#snapshotTimer.unref();
    this.#housekeepTimer = setInterval(() => void this.housekeep(), HOUSEKEEP_MS);
    this.#housekeepTimer.unref();
  }

  stop(): void {
    if (this.#snapshotTimer !== null) {
      clearInterval(this.#snapshotTimer);
      this.#snapshotTimer = null;
    }
    if (this.#housekeepTimer !== null) {
      clearInterval(this.#housekeepTimer);
      this.#housekeepTimer = null;
    }
    this.bus.stop();
  }

  /**
   * The slow sweeps. Public so the test suite and `/v1/admin/summary` can drive them
   * directly instead of waiting for a timer that a test should never depend on.
   *
   * Every failure is contained. A relay that is down must not take the arbiter with it,
   * and a sweep is by definition something that will be tried again.
   */
  async housekeep(): Promise<{ sessionsPruned: number; expired: number; uploadsRemoved: number; notices: number }> {
    if (this.#housekeeping) return { sessionsPruned: 0, expired: 0, uploadsRemoved: 0, notices: 0 };
    this.#housekeeping = true;
    try {
      const sessionsPruned = this.auth.prune();
      const expired = this.subs.sweep();
      const uploadsRemoved = await this.uploads.sweep();
      const notices = (await this.subs.sendDueReminders()).length;
      return { sessionsPruned, expired, uploadsRemoved, notices };
    } catch {
      return { sessionsPruned: 0, expired: 0, uploadsRemoved: 0, notices: 0 };
    } finally {
      this.#housekeeping = false;
    }
  }

  /* ---------------- control ---------------- */

  get paused(): boolean {
    return this.#paused;
  }

  /**
   * Pausing stops the arbiter from ADMITTING telemetry. It deliberately does not stop
   * the reporters: in a real deployment the agents keep transmitting regardless, and an
   * operator needs to see that wave being discarded and counted — not a silent lull that
   * hides whether the fleet is still alive.
   */
  setPaused(paused: boolean): void {
    this.#paused = paused;
    this.ledger.append("CONTROL", "-", paused ? "PAUSE" : "RESUME", Date.now());
  }

  setRate(tps: number): void {
    this.fleet.setTps(tps);
    this.ledger.append("CONTROL", "-", `RATE=${Math.floor(tps)}`, Date.now());
  }

  runScenario(name: Parameters<Fleet["scenario"]>[0], seconds: number): void {
    this.fleet.scenario(name, seconds);
    this.ledger.append("CONTROL", "-", `SCENARIO=${name}/${seconds}s`, Date.now());
  }

  bumpCorpus(n: number): void {
    this.#corpus += n;
  }

  /* ---------------- ingest integration ---------------- */

  /** Publish an adjudicated event to every observer. */
  emit(event: PublicEvent): void {
    this.bus.publish({ k: "E", batch: [event] });
  }

  tuning(): PublicTuning {
    return {
      windowMs: TUNING.windowMs,
      sampleCap: TUNING.sampleCap,
      subjectCap: TUNING.subjectCap,
      convictScore: TUNING.convictScore,
      pendingScore: TUNING.pendingScore,
      dwellMs: TUNING.dwellMs,
      decayMs: TUNING.decayMs,
      vetoScore: TUNING.vetoScore,
      ratePerSec: LIMITS.ratePerSec,
      rateBurst: LIMITS.rateBurst,
      maxSkewMs: MAX_SKEW_MS,
      corroborateSev: CORROBORATE_SEV,
      structuralCertaintySev: STRUCTURAL_CERTAINTY_SEV,
    };
  }

  counters(now: number): PublicCounters {
    const stats = this.arbiter.stats();
    const window = this.#tpsSamples;
    const oldest = window[0];
    const tps = oldest === undefined ? 0 : Math.max(0, Math.round(((stats.rx - oldest.rx) * 1000) / Math.max(1, now - oldest.t)));
    return {
      rx: stats.rx,
      drop: stats.drop,
      rej: stats.rej,
      rl: stats.rl,
      spf: stats.spf,
      sig: stats.sig,
      rpy: stats.rpy,
      conv: stats.conv,
      subj: stats.subj,
      evicted: stats.evicted,
      tps,
      p95: this.latency.p95(),
      ring: this.arbiter.roleCounts(),
      boot: this.bootIso,
    };
  }

  snapshot(): SnapshotResponse {
    const now = Date.now();
    return {
      subjects: this.arbiter.snapshot(now, SNAPSHOT_SUBJECTS),
      counters: this.counters(now),
      corpus: this.#corpus,
      tuning: this.tuning(),
      gates: this.arbiter.gateStages.map((g) => ({ gate: g.gate, label: g.label, seen: g.seen })),
      ledger: this.ledger.tail(48).map((r) => ({ seq: r.seq, ts: r.ts, kind: r.kind, su: r.su, dt: r.dt, h: r.h.slice(0, 10) })),
      chain: this.ledger.status(),
      agents: this.registry.size,
      uptimeMs: now - this.bootedAt,
      paused: this.#paused,
      scenario: this.fleet.scenarioName,
      rate: this.fleet.tps,
    };
  }

  /* ---------------- tick ---------------- */

  #tick(): void {
    const now = Date.now();
    this.arbiter.sweep(now);
    this.limiter.prune(now);
    this.requests.prune(now);

    const rx = this.arbiter.stats().rx;
    this.#tpsSamples.push({ t: now, rx });
    const cutoff = now - LIMITS.windowMs;
    while (this.#tpsSamples.length > 0) {
      const head = this.#tpsSamples[0];
      if (head === undefined || head.t >= cutoff) break;
      this.#tpsSamples.shift();
    }
    if (this.#tpsSamples.length > 64) this.#tpsSamples.splice(0, this.#tpsSamples.length - 64);

    this.#lastPublish = now;
    this.bus.publish({ k: "S", subj: this.arbiter.snapshot(now, SNAPSHOT_SUBJECTS), ctr: this.counters(now), corpus: this.#corpus });
  }

  get lastPublish(): number {
    return this.#lastPublish;
  }
}
