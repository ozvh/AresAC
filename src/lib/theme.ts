/**
 * Presentation vocabulary.
 *
 * Symbols are geometric or textual — no icon set, no glyph font, no sprite. A
 * console that renders state through pictograms is a console whose meaning has to
 * be learned twice.
 */
import type { GateId, LadderStep, RiskVerdict, Role, Disposition } from "@shared/protocol";
import { RING_BIT } from "@shared/protocol";

/** Verdict -> text colour class. The only place colour is assigned to a verdict. */
export const VERDICT_TEXT: Readonly<Record<RiskVerdict, string>> = {
  CLEAN: "text-clean",
  PENDING: "text-pending",
  FLAGGED: "text-flagged",
};

/** Verdict -> column glyph. Fixed width so ledger rows stay aligned. */
export const VERDICT_GLYPH: Readonly<Record<RiskVerdict, string>> = {
  CLEAN: "+",
  PENDING: "~",
  FLAGGED: "!",
};

export const VERDICT_LABEL: Readonly<Record<RiskVerdict, string>> = {
  CLEAN: "CLEAN  ",
  PENDING: "PENDING",
  FLAGGED: "FLAGGED",
};

export const STEP_LABEL: Readonly<Record<LadderStep, string>> = {
  NONE: "—",
  SUPPRESS: "SUPPRESS",
  STRIP: "STRIP-RIGHTS",
  VETO: "VETO-HANDLE",
  SHADOW: "SHADOW-QUEUE",
  CONVICT: "CONVICT",
};

/** Ladder depth as a fixed-width bar, so its width encodes the step. */
export const STEP_ORDER: readonly LadderStep[] = ["NONE", "SUPPRESS", "STRIP", "VETO", "SHADOW", "CONVICT"];

export const ROLE_RING_LABEL: Readonly<Record<Role, string>> = {
  KMOD: "R0",
  UMON: "R3",
  SRV: "EXT",
};

export const ROLE_LONG: Readonly<Record<Role, string>> = {
  KMOD: "RING 0 · KERNEL DRIVER",
  UMON: "RING 3 · USER-MODE SENTINEL",
  SRV: "EXTERNAL · SERVER ARBITER",
};

export interface RejectionClass {
  readonly key: string;
  readonly label: string;
  readonly detail: string;
  readonly critical: boolean;
  /** Counter field on PublicCounters that carries this class' total. */
  readonly field: "sig" | "spf" | "rpy" | "rl" | "rej" | "drop";
}

/**
 * Every way a sample can be refused before it is scored. Surfaced in the console
 * because a defence nobody can see failing is a defence nobody can trust.
 */
export const REJECTION_CLASSES: readonly RejectionClass[] = [
  {
    key: "SIG",
    label: "SIG",
    detail: "MAC absent or mismatched — an unauthenticated generator",
    critical: true,
    field: "sig",
  },
  {
    key: "ROLE",
    label: "ROLE",
    detail: "declared ring or evidence code contradicts the provisioned role",
    critical: true,
    field: "spf",
  },
  {
    key: "RPY",
    label: "RPY",
    detail: "sequence not monotonic — a replayed or rolled-back frame",
    critical: true,
    field: "rpy",
  },
  {
    key: "RL",
    label: "RL",
    detail: "input velocity exceeded — token bucket exhausted",
    critical: true,
    field: "rl",
  },
  {
    key: "REJ",
    label: "REJ",
    detail: "schema or clock refused before adjudication",
    critical: false,
    field: "rej",
  },
  {
    key: "DRP",
    label: "DRP",
    detail: "accepted but dropped — operator pause or table pressure",
    critical: false,
    field: "drop",
  },
];

/** Decode a corroboration mask into the rings that are backing this subject. */
export function ringsFor(mask: number): Role[] {
  const roles: Role[] = [];
  if ((mask & RING_BIT.KMOD) !== 0) roles.push("KMOD");
  if ((mask & RING_BIT.UMON) !== 0) roles.push("UMON");
  if ((mask & RING_BIT.SRV) !== 0) roles.push("SRV");
  return roles;
}

export function ringCount(mask: number): number {
  return ringsFor(mask).length;
}

/** Compact three-cell corroboration indicator, always three cells wide. */
export function maskCells(mask: number): string {
  return `${(mask & RING_BIT.KMOD) !== 0 ? "0" : "·"}${(mask & RING_BIT.UMON) !== 0 ? "3" : "·"}${
    (mask & RING_BIT.SRV) !== 0 ? "X" : "·"
  }`;
}

export const GATE_ORDER: readonly GateId[] = ["G0", "G1", "G2", "G3"];

export const GATE_DESCRIPTION: Readonly<Record<GateId, string>> = {
  G0: "SENSOR — raw callback fired, nothing assumed",
  G1: "SIGN-TRUST — code identity resolved against a trusted root",
  G2: "CORPUS — hash matched against the fleet-synced allowlist",
  G3: "BEHAVIOURAL — time-windowed model, cross-ring corroboration required",
};

export const DISPOSITION_TEXT: Readonly<Record<Disposition, string>> = {
  ACCEPT: "text-dim",
  SUPPRESS: "text-clean",
  ESCALATE: "text-pending",
  CONTAIN: "text-pending",
  DENY: "text-flagged",
};

export const STEP_TEXT: Readonly<Record<LadderStep, string>> = {
  NONE: "text-dimmer",
  SUPPRESS: "text-clean",
  STRIP: "text-pending",
  VETO: "text-pending",
  SHADOW: "text-pending",
  CONVICT: "text-flagged",
};
