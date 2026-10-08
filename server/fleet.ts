/**
 * Synthetic fleet. SERVER-SIDE ONLY — and that placement is the point.
 *
 * The console is a zero-trust observer: it never originates telemetry, so nothing
 * it can do (or be tricked into doing) can move a verdict. To have a live system
 * to observe, the load is generated here, in the arbiter process, and pushed
 * through the *real* HTTP ingest path — loopback socket, real MAC verification,
 * real schema validation, real rate limiter. Nothing about this file bypasses the
 * defences it is exercising.
 *
 * Profiles are chosen so the doctrine is falsifiable from the console:
 *   OVERLAY   signed overlay hooks        -> must never leave CLEAN
 *   CLEAN     allowlist hits              -> must suppress, not escalate
 *   AIM       external behavioural only   -> may reach PENDING, must never convict
 *   CHEAT     structural, two rings       -> must convict
 *   SPOOF     forged ring claim + replay  -> must be rejected before adjudication
 */
import { createHash } from "node:crypto";
import {
  PROTOCOL_VERSION,
  canonicalEvent,
  type EvidenceCode,
  type IngestEvent,
  type RingId,
  type Role,
  type ScenarioName,
} from "../shared/protocol.ts";
import { signEvent, type AgentRegistry, type Agent } from "./agents.ts";

export const PROFILES = ["OVERLAY", "CLEAN", "AIM", "CHEAT", "SPOOF"] as const;
export type Profile = (typeof PROFILES)[number];

type Roster = Record<Role, Agent>;
type Counters = Record<Role, number>;

type Session = {
  readonly subject: string;
  readonly profile: Profile;
  readonly agents: Roster;
  readonly seq: Counters;
};

/** mulberry32: small, fast, deterministic. Reproducible runs beat pretty randomness. */
function mulberry32(seed: number): () => number {
  let a = seed >>> 0;
  return () => {
    a = (a + 0x6d2b79f5) >>> 0;
    let t = a;
    t = Math.imul(t ^ (t >>> 15), t | 1);
    t ^= t + Math.imul(t ^ (t >>> 7), t | 61);
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };
}

function digestOf(seed: string): string {
  return createHash("sha256").update(seed, "utf8").digest("hex").slice(0, 32);
}

/** Evidence a profile is allowed to emit, with the ring that owns the code. */
const PROFILE_CODES: Readonly<Record<Profile, ReadonlyArray<{ c: EvidenceCode; r: Role; w: number }>>> = {
  OVERLAY: [
    { c: "XB", r: "UMON", w: 5 },
    { c: "XB", r: "KMOD", w: 2 },
    { c: "XD", r: "UMON", w: 3 },
  ],
  CLEAN: [
    { c: "XD", r: "UMON", w: 4 },
    { c: "XD", r: "KMOD", w: 2 },
    { c: "XB", r: "UMON", w: 1 },
  ],
  AIM: [
    { c: "X8", r: "SRV", w: 4 },
    { c: "XA", r: "SRV", w: 2 },
    { c: "X7", r: "UMON", w: 3 },
    { c: "X9", r: "SRV", w: 2 },
  ],
  CHEAT: [
    { c: "X1", r: "UMON", w: 3 },
    { c: "X6", r: "KMOD", w: 3 },
    { c: "X6", r: "UMON", w: 2 },
    { c: "X3", r: "UMON", w: 1 },
    { c: "X2", r: "KMOD", w: 2 },
    { c: "X5", r: "KMOD", w: 1 },
  ],
  SPOOF: [
    { c: "X8", r: "SRV", w: 1 },
    { c: "X7", r: "UMON", w: 1 },
  ],
};

/** Codes a SPOOF session deliberately misfiles under the wrong ring. */
const FORGED_CODE: EvidenceCode = "XC";

export type FleetConfig = {
  readonly sessions: number;
  readonly tps: number;
  readonly origin: string;
  readonly seed: number;
};

export type FleetStats = {
  /** Telemetry samples emitted, not HTTP requests. */
  readonly emitted: number;
  /** Ingest requests issued to the loopback listener. */
  readonly requests: number;
  readonly failed: number;
  readonly inFlight: number;
  readonly tps: number;
  readonly sessions: number;
};

const TICK_MS = 50;

export class Fleet {
  readonly #sessions: Session[] = [];
  readonly #rand: () => number;
  #timer: NodeJS.Timeout | null = null;
  #tps: number;
  #emitted = 0;
  #requests = 0;
  #failed = 0;
  #inFlight = 0;
  #origin: string;
  #scenario: { name: ScenarioName; until: number } | null = null;
  #carry = 0;
  #lastWindowEmitted = 0;
  #lastWindowAt = Date.now();
  #measuredTps = 0;

  constructor(registry: AgentRegistry, config: FleetConfig) {
    this.#rand = mulberry32(config.seed);
    this.#tps = config.tps;
    this.#origin = config.origin;

    const profiles = PROFILES;
    for (let i = 0; i < config.sessions; i += 1) {
      const profile = profiles[i % profiles.length] ?? "CLEAN";
      this.#sessions.push({
        subject: digestOf(`subject:${i}`),
        profile,
        agents: {
          KMOD: registry.enroll("KMOD"),
          UMON: registry.enroll("UMON"),
          SRV: registry.enroll("SRV"),
        },
        seq: { KMOD: 0, UMON: 0, SRV: 0 },
      });
    }
  }

  get sessions(): number {
    return this.#sessions.length;
  }

  get tps(): number {
    return this.#tps;
  }

  /** Subjects currently owned by the fleet, for the console's spawn overlay. */
  get subjectDigests(): readonly string[] {
    return this.#sessions.map((s) => s.subject);
  }

  start(): void {
    if (this.#timer !== null) return;
    this.#timer = setInterval(() => {
      this.#tick().catch(() => {
        this.#failed += 1;
      });
    }, TICK_MS);
    this.#timer.unref();
  }

  stop(): void {
    if (this.#timer !== null) {
      clearInterval(this.#timer);
      this.#timer = null;
    }
  }

  setTps(next: number): void {
    this.#tps = Math.max(0, Math.min(200_000, Math.floor(next)));
  }

  /** Retarget the fleet after the listener has resolved its actual port. */
  setOrigin(origin: string): void {
    this.#origin = origin;
  }

  get scenarioName(): ScenarioName | null {
    return this.#scenario === null ? null : this.#scenario.name;
  }

  /** Arm an adversary profile for `seconds`. Overlapping arms replace each other. */
  scenario(name: ScenarioName, seconds: number): void {
    const now = Date.now();
    if (seconds <= 0) {
      this.#scenario = null;
      return;
    }
    this.#scenario = { name, until: now + seconds * 1000 };
  }

  stats(): FleetStats {
    const now = Date.now();
    const elapsed = now - this.#lastWindowAt;
    if (elapsed >= 1000) {
      this.#measuredTps = Math.round(((this.#emitted - this.#lastWindowEmitted) * 1000) / elapsed);
      this.#lastWindowEmitted = this.#emitted;
      this.#lastWindowAt = now;
    }
    return {
      emitted: this.#emitted,
      requests: this.#requests,
      failed: this.#failed,
      inFlight: this.#inFlight,
      tps: this.#measuredTps,
      sessions: this.#sessions.length,
    };
  }

  /* ---------------- emission ---------------- */

  #pickSession(): Session {
    const idx = Math.floor(this.#rand() * this.#sessions.length);
    return this.#sessions[idx] ?? this.#sessions[0]!;
  }

  #weightedCode(session: Session): { c: EvidenceCode; r: Role } {
    const table = PROFILE_CODES[session.profile];
    let total = 0;
    for (const entry of table) total += entry.w;
    let roll = this.#rand() * total;
    for (const entry of table) {
      roll -= entry.w;
      if (roll <= 0) return { c: entry.c, r: entry.r };
    }
    const fallback = table[0];
    return fallback === undefined ? { c: "XD", r: "UMON" } : { c: fallback.c, r: fallback.r };
  }

  async #tick(): Promise<void> {
    const now = Date.now();
    if (this.#scenario !== null && now > this.#scenario.until) this.#scenario = null;

    const scenario = this.#scenario?.name ?? null;
    const scale = scenario === "CAPACITY" ? 25 : scenario === null ? 1 : 2;
    const budget = (this.#tps * TICK_MS * scale) / 1000 + this.#carry;
    let events = Math.floor(budget);
    this.#carry = budget - events;

    if (events <= 0) return;
    if (events > 2000) events = 2000; // per-tick ceiling: never let one tick stall the loop

    const outbound: Array<Promise<void>> = [];

    while (events > 0) {
      const session = this.#pickSession();
      const take = Math.min(events, 24, 1 + Math.floor(this.#rand() * 8));
      events -= take;

      // A batch is signed with one principal's key, and the arbiter refuses any
      // batch spanning more than one agent — so events are grouped by the ring that
      // produced them and posted as one request per ring. Collapsing them into a
      // single request would be a forgery attempt by construction.
      const byRole = new Map<Role, IngestEvent[]>();
      for (let i = 0; i < take; i += 1) {
        const chosen = this.#choose(session, scenario, now);
        const agent = session.agents[chosen.r];
        const seq = this.#bump(session, chosen.r);
        const event: IngestEvent = {
          v: PROTOCOL_VERSION,
          a: agent.id,
          k: session.subject,
          s: seq,
          t: now,
          r: chosen.ring,
          c: chosen.c,
          m: chosen.m,
        };
        const group = byRole.get(chosen.r);
        if (group === undefined) byRole.set(chosen.r, [event]);
        else group.push(event);
      }

      for (const [role, batch] of byRole) {
        outbound.push(this.#post(session.agents[role], batch));
        this.#emitted += batch.length;
        this.#requests += 1;
      }
      if (outbound.length >= 16) break; // bound per-tick fan-out
    }

    this.#inFlight += outbound.length;
    await Promise.all(outbound).catch(() => undefined);
    this.#inFlight = Math.max(0, this.#inFlight - outbound.length);
  }

  #bump(session: Session, role: Role): number {
    session.seq[role] += 1;
    return session.seq[role];
  }

  #choose(
    session: Session,
    scenario: ScenarioName | null,
    now: number,
  ): { c: EvidenceCode; r: Role; ring: RingId; m: number } {
    const base = this.#weightedCode(session);
    let { c: code } = base;
    let { r: role } = base;

    if (scenario === "AIMBOT_ONLY") {
      code = "X8";
      role = "SRV";
    } else if (scenario === "OVERLAY_NOISE") {
      code = this.#rand() < 0.7 ? "XB" : "XD";
      role = "UMON";
    } else if (scenario === "KERNEL_CHEAT" && session.profile === "CHEAT") {
      code = this.#rand() < 0.5 ? "X2" : "X6";
      role = this.#rand() < 0.5 ? "KMOD" : "UMON";
      if (code === "X2") role = "KMOD";
    } else if (scenario === "SPOOF_ATTEMPT" && session.profile === "SPOOF") {
      // Deliberately misfile a kernel-only code under the user-mode ring.
      code = FORGED_CODE;
      role = "UMON";
    }

    // A SPOOF session occasionally repeats a sequence number it already used.
    const replay = session.profile === "SPOOF" && this.#rand() < 0.25;
    if (replay && session.seq[role] > 1) session.seq[role] -= 1;

    const ring: RingId = role === "KMOD" ? 0 : role === "UMON" ? 3 : -1;
    const m = Math.round(this.#rand() * 10_000) / 100 + (now % 97);
    return { c: code, r: role, ring, m };
  }

  async #post(agent: Agent, batch: ReadonlyArray<IngestEvent>): Promise<void> {
    const canonical = batch.map((e) => canonicalEvent(e)).join("\n");
    const sig = signEvent(agent.key, canonical);
    const body = JSON.stringify(
      batch.map((e) => ({ v: e.v, a: e.a, k: e.k, s: e.s, t: e.t, r: e.r, c: e.c, m: e.m })),
    );
    try {
      await fetch(`${this.#origin}/v1/ingest`, {
        method: "POST",
        headers: { "content-type": "application/json", "x-ares-sig": sig },
        body,
        // The fleet must never hold a socket open past its usefulness.
        signal: AbortSignal.timeout(4_000),
      });
    } catch {
      this.#failed += 1;
    }
  }
}
