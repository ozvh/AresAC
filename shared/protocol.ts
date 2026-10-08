/**
 * ARES wire protocol. Single source of truth for the arbiter and the operator console.
 *
 * DESIGN CONSTRAINTS (why this file looks the way it does):
 *  1. Field names are compressed. The console is an untrusted display surface; nothing
 *     about the scoring model may be reconstructed from the shape of a payload.
 *  2. Every ingest field is a closed primitive type. No open records, no `unknown`
 *     pass-through, no optional catch-all bags.
 *  3. Severity, classification and gate derivation live in `server/catalog.ts` and are
 *     NEVER shipped to the client. The console receives an already-adjudicated verdict
 *     and cannot mint one.
 *  4. Ring identity is declared by the sender but is authoritative only after the
 *     arbiter matches it to the agent's provisioned role (see `server/agents.ts`).
 */

/** Bumped on any breaking change to the ingest or frame layout. */
export const PROTOCOL_VERSION = 1 as const;

/* ------------------------------------------------------------------ */
/*  Hard limits. Enforced server-side; declared here so both sides      */
/*  agree on the numbers rather than scattering magic constants.        */
/* ------------------------------------------------------------------ */
export const LIMITS = {
  /** Maximum accepted request body for /v1/ingest. */
  bodyBytes: 16 * 1024,
  /** Maximum events accepted in a single ingest request. */
  batchMax: 64,
  /** Replay buffer depth held by the arbiter for Last-Event-ID resume. */
  replayRing: 4096,
  /** Client-side event ring. Oldest entries are discarded, never queued unbounded. */
  consoleRing: 60000,
  /** Token bucket: sustained rate per agent, and burst ceiling. */
  ratePerSec: 120,
  rateBurst: 240,
  /** Operator control plane: minimum milliseconds between accepted mutations. */
  controlMinIntervalMs: 250,
  /** Rejected-before-adjudication counter window for /v1/health telemetry. */
  windowMs: 5000,
} as const;

/** Evidence codes are opaque. Semantics live in server/catalog.ts. */
export const EVIDENCE_CODES = [
  "X1", // unsigned image mapped into the protected address space
  "X2", // foreign handle holding write access to the protected process
  "X3", // executable-section integrity mismatch
  "X4", // debug object attached
  "X5", // thread started outside every mapped image
  "X6", // corpus signature hit
  "X7", // input timing entropy below the human floor
  "X8", // aim trajectory outside the deviation model
  "X9", // movement replay divergence
  "XA", // hit-registration inconsistency
  "XB", // overlay/compositor hook present
  "XC", // unsigned kernel image load attempt
  "XD", // corpus allowlist match
] as const;

export type EvidenceCode = (typeof EVIDENCE_CODES)[number];

const EVIDENCE_SET: ReadonlySet<string> = new Set(EVIDENCE_CODES);

export function isEvidenceCode(value: unknown): value is EvidenceCode {
  return typeof value === "string" && EVIDENCE_SET.has(value);
}

/* ------------------------------------------------------------------ */
/*  Rings                                                              */
/* ------------------------------------------------------------------ */

export type Role = "UMON" | "KMOD" | "SRV";

export const ROLE_RING: Readonly<Record<Role, RingId>> = {
  KMOD: 0,
  UMON: 3,
  SRV: -1,
};

export type RingId = 0 | 3 | -1;

/** Bit assignment for the corroboration mask. Stable across the wire. */
export const RING_BIT: Readonly<Record<Role, number>> = {
  KMOD: 0b001,
  UMON: 0b010,
  SRV: 0b100,
};

export const RINGS_WITH_SIGNAL = 0b111;

export function isRole(value: unknown): value is Role {
  return value === "UMON" || value === "KMOD" || value === "SRV";
}

/* ------------------------------------------------------------------ */
/*  Ingest (agent -> arbiter)                                          */
/* ------------------------------------------------------------------ */

/**
 * One telemetry sample. Keys are intentionally 1-2 characters: the payload is
 * produced by a resident agent and travels over a hostile link.
 *
 *  v  protocol version
 *  a  agent id, 16 hex chars
 *  k  subject digest, 32 hex chars (never a raw account identifier)
 *  s  monotonic sequence per agent, uint32, strictly increasing
 *  t  sender clock, milliseconds, advisory only — never used for ordering
 *  r  declared ring, must equal the role provisioned for `a`
 *  c  evidence code
 *  m  measurement, finite, |m| <= 1e6
 */
export type IngestEvent = {
  v: typeof PROTOCOL_VERSION;
  a: string;
  k: string;
  s: number;
  t: number;
  r: RingId;
  c: EvidenceCode;
  m: number;
};

/** Canonical MAC input. Deterministic: number formatting follows ECMA-262 exactly. */
export function canonicalEvent(e: IngestEvent): string {
  return `${e.v}|${e.a}|${e.s}|${e.t}|${e.r}|${e.c}|${e.m}|${e.k}`;
}

/* ------------------------------------------------------------------ */
/*  Adjudicated output (arbiter -> console)                            */
/* ------------------------------------------------------------------ */

export type RiskVerdict = "CLEAN" | "PENDING" | "FLAGGED";

/** Response ladder. Monotone within an episode; only review or decay lowers it. */
export type LadderStep = "NONE" | "SUPPRESS" | "STRIP" | "VETO" | "SHADOW" | "CONVICT";

export type GateId = "G0" | "G1" | "G2" | "G3";

export type Disposition = "ACCEPT" | "SUPPRESS" | "CONTAIN" | "ESCALATE" | "DENY";

/** A single adjudicated event, as displayed by the console. */
export type PublicEvent = {
  /** Authoritative global sequence assigned at receipt. */
  q: number;
  /** Authoritative receipt timestamp (arbiter clock). */
  ts: number;
  /** Agent id, truncated to 8 hex for display. */
  ag: string;
  role: Role;
  /** Subject digest, truncated to 12 hex for display. */
  su: string;
  c: EvidenceCode;
  /** Server-assigned severity 0..100. Not derivable by the client. */
  sev: number;
  gate: GateId;
  dsp: Disposition;
};

export type PublicSubject = {
  su: string;
  vd: RiskVerdict;
  /** Corroboration mask, see RING_BIT. */
  rm: number;
  /** Arbiter score, 0..1, two decimals. */
  sc: number;
  /** Milliseconds sustained above the conviction threshold. */
  dw: number;
  st: LadderStep;
  /** Capability containment applied to the subject's agent. */
  ct: boolean;
  /** Evidence samples retained for this subject in the window. */
  n: number;
  last: number;
};

export type RoleCounters = Record<Role, number>;

export type PublicCounters = {
  /** Accepted events. */
  rx: number;
  /** Events dropped by operator pause or ring overflow. */
  drop: number;
  /** Events rejected before adjudication. */
  rej: number;
  /** Rejections caused specifically by rate limiting. */
  rl: number;
  /** Role-mismatch rejections (spoofed ring claims). */
  spf: number;
  /** Signature failures. */
  sig: number;
  /** Replay/idempotency rejections. */
  rpy: number;
  /** Convictions issued. */
  conv: number;
  /** Tracked subjects. */
  subj: number;
  /** Events per second, 5s window. */
  tps: number;
  /** p95 adjudication latency in MICROSECONDS per sample. Sub-millisecond by design. */
  p95: number;
  ring: RoleCounters;
  /** ISO timestamp of arbiter boot. */
  boot: string;
  /** Subjects evicted from the table to respect the cap. */
  evicted: number;
};

export type ServerFrame =
  | { k: "E"; batch: readonly PublicEvent[] }
  | { k: "S"; subj: readonly PublicSubject[]; ctr: PublicCounters; corpus: number }
  | { k: "R"; reason: string };

/** Adversary profiles the arbiter can be exercised against. */
export const SCENARIOS = [
  "AIMBOT_ONLY", // external-only behavioural signal: must never convict
  "KERNEL_CHEAT", // structural, two rings, must convict
  "OVERLAY_NOISE", // signed overlay traffic: must never even reach PENDING
  "SPOOF_ATTEMPT", // forged ring claim + replayed frames: must be rejected upstream
  "CAPACITY", // sustained flood: must be rate-limited without dropping the fleet
] as const;

export type ScenarioName = (typeof SCENARIOS)[number];

/** Operator control plane. Same-origin + operator token required. */
export type ControlAction =
  | { op: "PAUSE" }
  | { op: "RESUME" }
  | { op: "RATE"; tps: number }
  | { op: "SCENARIO"; name: ScenarioName }
  | { op: "RELEASE"; su: string }
  | { op: "FLAG"; su: string };

export type ControlResult = { ok: true; applied: string } | { ok: false; e: ApiErrorCode; msg: string };

/** Read-only view of the arbiter's live thresholds. Operators need these; they confer no authority. */
export type PublicTuning = {
  windowMs: number;
  sampleCap: number;
  subjectCap: number;
  convictScore: number;
  pendingScore: number;
  dwellMs: number;
  decayMs: number;
  vetoScore: number;
  ratePerSec: number;
  rateBurst: number;
  maxSkewMs: number;
  /** Severity at or above which a sample corroborates its reporting ring. */
  corroborateSev: number;
  /** Severity at or above which a structural proof permits single-ring conviction. */
  structuralCertaintySev: number;
};

export type GateStageView = { gate: GateId; label: string; seen: number };

export type LedgerView = {
  seq: number;
  ts: number;
  kind: string;
  su: string;
  dt: string;
  h: string;
};

export type ChainView = {
  head: string;
  length: number;
  sealed: number;
  broken: boolean;
  brokenAt: number | null;
};

/** Full state sync. Used at boot and after any stream reset. */
export type SnapshotResponse = {
  subjects: PublicSubject[];
  counters: PublicCounters;
  corpus: number;
  tuning: PublicTuning;
  gates: GateStageView[];
  ledger: LedgerView[];
  chain: ChainView;
  agents: number;
  uptimeMs: number;
  /** Operator pause state. Accepted samples are discarded while paused. */
  paused: boolean;
  /** Armed adversary profile, or null. */
  scenario: string | null;
  /** Current fleet emission target, events per second. */
  rate: number;
};

/* ------------------------------------------------------------------ */
/*  Errors                                                             */
/* ------------------------------------------------------------------ */

export const API_ERROR_CODES = [
  "BAD_METHOD",
  "BAD_CT",
  "TOO_LARGE",
  "MALFORMED",
  "SCHEMA",
  "SIG",
  "ROLE",
  "REPLAY",
  "RATE",
  "STALE",
  "FORBIDDEN",
  "NOT_FOUND",
] as const;

export type ApiErrorCode = (typeof API_ERROR_CODES)[number];

export type ApiError = { e: ApiErrorCode; msg: string };

/* ------------------------------------------------------------------ */
/*  Display metadata (safe: presentation only, no scoring authority)    */
/* ------------------------------------------------------------------ */

export const CODE_LABEL: Readonly<Record<EvidenceCode, string>> = {
  X1: "IMG_UNSIGNED_MAP",
  X2: "HANDLE_VM_WRITE",
  X3: "TEXT_INTEGRITY",
  X4: "DBG_OBJECT",
  X5: "THREAD_FOREIGN_ORIGIN",
  X6: "CORPUS_HIT",
  X7: "INPUT_ENTROPY_LOW",
  X8: "AIM_DEVIATION",
  X9: "MOVE_REPLAY_DIVERGE",
  XA: "HITREG_INCONSISTENT",
  XB: "OVERLAY_HOOK",
  XC: "KMD_UNSIGNED_LOAD",
  XD: "CORPUS_ALLOWLIST",
};

export const GATE_LABEL: Readonly<Record<GateId, string>> = {
  G0: "SENSOR",
  G1: "SIGN-TRUST",
  G2: "CORPUS",
  G3: "BEHAVIOURAL",
};

/* ------------------------------------------------------------------ */
/*  Defensive decoders                                                 */
/* ------------------------------------------------------------------ */

function isFiniteNumber(value: unknown): value is number {
  return typeof value === "number" && Number.isFinite(value);
}

function isMask(value: unknown): value is number {
  return isFiniteNumber(value) && Number.isInteger(value) && value >= 0 && value <= 7;
}

export function isPublicEvent(value: unknown): value is PublicEvent {
  if (typeof value !== "object" || value === null) return false;
  const r = value as Record<string, unknown>;
  return (
    isFiniteNumber(r["q"]) &&
    isFiniteNumber(r["ts"]) &&
    typeof r["ag"] === "string" &&
    typeof r["su"] === "string" &&
    isRole(r["role"]) &&
    isEvidenceCode(r["c"]) &&
    isFiniteNumber(r["sev"]) &&
    r["sev"] >= 0 &&
    r["sev"] <= 100 &&
    typeof r["gate"] === "string" &&
    r["gate"] in GATE_LABEL &&
    typeof r["dsp"] === "string"
  );
}

const VERDICTS: ReadonlySet<string> = new Set<RiskVerdict>(["CLEAN", "PENDING", "FLAGGED"]);
const STEPS: ReadonlySet<string> = new Set<LadderStep>([
  "NONE",
  "SUPPRESS",
  "STRIP",
  "VETO",
  "SHADOW",
  "CONVICT",
]);

export function isPublicSubject(value: unknown): value is PublicSubject {
  if (typeof value !== "object" || value === null) return false;
  const r = value as Record<string, unknown>;
  return (
    typeof r["su"] === "string" &&
    typeof r["vd"] === "string" &&
    VERDICTS.has(r["vd"]) &&
    isMask(r["rm"]) &&
    isFiniteNumber(r["sc"]) &&
    isFiniteNumber(r["dw"]) &&
    typeof r["st"] === "string" &&
    STEPS.has(r["st"]) &&
    typeof r["ct"] === "boolean" &&
    isFiniteNumber(r["n"]) &&
    isFiniteNumber(r["last"])
  );
}

/** Parse one SSE payload line into a frame, or null when it is not worth keeping. */
export function decodeFrame(raw: string): ServerFrame | null {
  let parsed: unknown;
  try {
    parsed = JSON.parse(raw);
  } catch {
    return null;
  }
  if (typeof parsed !== "object" || parsed === null) return null;
  const r = parsed as Record<string, unknown>;
  if (r["k"] === "E") {
    const batch = r["batch"];
    if (!Array.isArray(batch)) return null;
    const clean: PublicEvent[] = [];
    for (const item of batch) {
      if (isPublicEvent(item)) clean.push(item);
    }
    return { k: "E", batch: clean };
  }
  if (r["k"] === "S") {
    const subjRaw = r["subj"];
    const ctr = r["ctr"];
    if (!Array.isArray(subjRaw) || typeof ctr !== "object" || ctr === null) return null;
    const subj: PublicSubject[] = [];
    for (const item of subjRaw) {
      if (isPublicSubject(item)) subj.push(item);
    }
    return { k: "S", subj, ctr: ctr as PublicCounters, corpus: isFiniteNumber(r["corpus"]) ? r["corpus"] : 0 };
  }
  if (r["k"] === "R" && typeof r["reason"] === "string") {
    return { k: "R", reason: r["reason"] };
  }
  return null;
}

/* ------------------------------------------------------------------ */
/*  Build request intake (the one public, unauthenticated surface)      */
/* ------------------------------------------------------------------ */

/**
 * Build channels a requester may ask for. A closed set: the requested channel is
 * written into an audit record and into a mail subject, and free text in either is
 * an injection surface with no upside.
 */
export const BUILD_PROFILES = ["RETAIL", "DEVELOPMENT", "SOURCE", "EVALUATION"] as const;

export type BuildProfile = (typeof BUILD_PROFILES)[number];

const PROFILE_SET: ReadonlySet<string> = new Set<string>(BUILD_PROFILES);

export function isBuildProfile(value: unknown): value is BuildProfile {
  return typeof value === "string" && PROFILE_SET.has(value);
}

/**
 * Limits for POST /v1/request.
 *
 * This is the only endpoint in the system that accepts unauthenticated input AND
 * causes an outbound side effect, which makes it the only amplification surface
 * here. Every bound below exists to constrain that amplification — a public form
 * that emits mail is a spam relay unless it is fenced, and the fence has to be
 * server-side because the fence the client sees is the client's to remove.
 */
export const REQUEST_LIMITS = {
  /** Byte ceiling for the request body. Well below the ingest ceiling on purpose. */
  bodyBytes: 8 * 1024,
  nameMin: 2,
  nameMax: 80,
  emailMax: 254,
  orgMax: 120,
  /** A note under this length is not a request, it is an empty submission. */
  noteMin: 8,
  noteMax: 2000,
  /**
   * Minimum age of the form before a submission is credible. ADVISORY ONLY: the
   * value is client-supplied and therefore forgeable. It filters scripted
   * submissions that never rendered a page; it is not a security control, and no
   * decision that matters depends on it.
   */
  dwellMs: 2_000,
  /** Per-source sustained submissions per minute, and burst ceiling. */
  sourcePerMin: 2,
  sourceBurst: 2,
  /** Process-wide ceiling, so a distributed spray cannot spend the relay budget. */
  globalPerMin: 20,
  globalBurst: 20,
  /** Repeat submissions from one source for one address are folded inside this window. */
  dedupeMs: 600_000,
  /** Upper bound on distinct dedupe keys retained, so a spray cannot grow the map. */
  dedupeCap: 4_096,
} as const;

/** Payload posted by the request form. Primitive, single-valued keys only. */
export type BuildRequestInput = {
  /** callsign of the requester */
  nm: string;
  /** reply address */
  em: string;
  /** organisation; may be empty */
  org: string;
  /** requested build channel */
  tgt: BuildProfile;
  /** free-text note */
  msg: string;
  /** honeypot field: a person never fills this in */
  hp: string;
  /** milliseconds the form was on screen before submission; advisory */
  el: number;
};

/** The closed key set of the request payload. */
export const REQUEST_KEYS = ["nm", "em", "org", "tgt", "msg", "hp", "el"] as const;

/**
 * Acknowledgement.
 *
 * Deliberately says nothing about how or whether the request was relayed. Whether
 * the relay is configured, throttled or spooling is operator information; it is
 * written to the ledger, not handed to an unauthenticated submitter.
 */
export type BuildRequestAck = { ok: true; ref: string };

export type RequestRelayState = "DELIVERED" | "SPOOLED" | "FAILED";

/* ------------------------------------------------------------------ */
/*  Accounts (customer and administrator surfaces)                      */
/* ------------------------------------------------------------------ */

/**
 * Account roles.
 *
 * Deliberately NOT the telemetry `Role` type. A reporting ring and an account are
two different authorities, and giving them one name would invite a value of one to be
passed where the other is expected — which is the shape of an authorisation bug.
 */
export type AccountRole = "CUSTOMER" | "ADMIN";

export type AccountStatus = "ACTIVE" | "SUSPENDED" | "CLOSED";

export type ConsentKind = "TERMS" | "PRIVACY" | "MARKETING";

export type PlanName = "EVALUATION" | "RETAIL" | "SOURCE";

/** Presentation only. The server owns the prices and the period lengths. */
export const PLAN_LABEL: Readonly<Record<PlanName, string>> = {
  EVALUATION: "evaluation — fixed term, no charge",
  RETAIL: "retail — signed build",
  SOURCE: "source — distribution and headers",
};

export const CONSENT_LABEL: Readonly<Record<ConsentKind, string>> = {
  TERMS: "terms of service",
  PRIVACY: "privacy policy",
  MARKETING: "renewal and product email",
};

/** What the server tells a signed-in page about itself. Never carries a session secret. */
export type AccountUser = {
  email: string;
  displayName: string;
  role: AccountRole;
  mustChangePassword: boolean;
};

export type ConsentView = {
  kind: ConsentKind;
  version: string;
  grantedAt: number;
  withdrawn: boolean;
};

export type SubscriptionView = {
  id: string;
  plan: PlanName;
  status: "ACTIVE" | "CANCELLED" | "EXPIRED";
  currentPeriodEnd: number;
  autoRenew: boolean;
  cancelledAt: number | null;
  cancelEffectiveAt: number | null;
  noticeDays: number;
  amountCents: number;
};

export type UploadView = {
  id: string;
  originalName: string;
  bytes: number;
  verdict: "ACCEPTED" | "QUARANTINED" | "REJECTED";
  createdAt: number;
  expiresAt: number;
  deleted: boolean;
};

/** Answer to `GET /v1/auth/me`. The csrf token is the only credential in this payload. */
export type MeResponse = {
  ok: true;
  csrf: string;
  user: AccountUser;
  consents: ConsentView[];
  subscription: SubscriptionView | null;
  uploads: UploadView[];
  retentionDays: number;
};

/** Answer to signup, login and password change. Sets the session cookie. */
export type AuthAck = { ok: true; csrf: string; user: AccountUser };

export type AdminUserView = {
  id: string;
  email: string;
  displayName: string;
  role: AccountRole;
  status: AccountStatus;
  createdAt: number;
  lastLoginAt: number | null;
};

export type AdminAuditView = {
  seq: number;
  ts: number;
  actorRole: "ANON" | "CUSTOMER" | "ADMIN" | "SYSTEM";
  actorId: string | null;
  action: string;
  subjectId: string | null;
  outcome: "OK" | "REFUSED";
  detail: string;
};

/** Aggregate intake counters. Reported on /v1/health; never carries requester data. */
export type RequestStats = {
  /** Submissions that passed every gate and were handed to the relay. */
  accepted: number;
  /** Submissions refused on shape or bounds. */
  refused: number;
  /** Submissions refused by a velocity gate. */
  throttled: number;
  /** Submissions that filled the honeypot field. */
  trapped: number;
  /** Submissions folded into an earlier identical request. */
  duplicates: number;
  delivered: number;
  spooled: number;
  failed: number;
};
