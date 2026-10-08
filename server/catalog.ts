/**
 * Evidence catalogue. SERVER-ONLY AUTHORITY.
 *
 * This table is the reason the console can never mint a verdict: severity,
 * classification, authorised reporting ring and pipeline gate are all resolved
 * here, from a code the agent merely asserts. A fully compromised client can
 * fabricate codes and measurements; it cannot fabricate the weight they carry.
 */
import { RING_BIT, type EvidenceCode, type GateId, type Role } from "../shared/protocol.ts";

export type EvidenceClass = "STRUCTURAL" | "BEHAVIORAL" | "BENIGN";

export type CatalogEntry = {
  /** 0..100. Server-assigned weight. */
  readonly sev: number;
  readonly cls: EvidenceClass;
  /** Bitmask of roles permitted to report this code. Spoofing a higher ring is rejected. */
  readonly srcMask: number;
  /** Pipeline stage that resolved the sample. */
  readonly gate: GateId;
};

const M = RING_BIT;

export const CATALOG: Readonly<Record<EvidenceCode, CatalogEntry>> = {
  X1: { sev: 90, cls: "STRUCTURAL", srcMask: M.UMON, gate: "G1" },
  X2: { sev: 95, cls: "STRUCTURAL", srcMask: M.KMOD, gate: "G1" },
  X3: { sev: 92, cls: "STRUCTURAL", srcMask: M.UMON, gate: "G1" },
  X4: { sev: 72, cls: "BEHAVIORAL", srcMask: M.UMON, gate: "G3" },
  X5: { sev: 88, cls: "STRUCTURAL", srcMask: M.KMOD, gate: "G1" },
  X6: { sev: 85, cls: "STRUCTURAL", srcMask: M.UMON | M.KMOD, gate: "G2" },
  X7: { sev: 45, cls: "BEHAVIORAL", srcMask: M.UMON, gate: "G3" },
  X8: { sev: 80, cls: "BEHAVIORAL", srcMask: M.SRV, gate: "G3" },
  X9: { sev: 82, cls: "BEHAVIORAL", srcMask: M.SRV, gate: "G3" },
  XA: { sev: 78, cls: "BEHAVIORAL", srcMask: M.SRV, gate: "G3" },
  XB: { sev: 8, cls: "BENIGN", srcMask: M.UMON | M.KMOD, gate: "G2" },
  XC: { sev: 86, cls: "STRUCTURAL", srcMask: M.KMOD, gate: "G1" },
  XD: { sev: 0, cls: "BENIGN", srcMask: M.UMON | M.KMOD | M.SRV, gate: "G2" },
};

/** Severity at or above which a sample corroborates its reporting ring. */
export const CORROBORATE_SEV = 60;

/**
 * Severity at or above which structural evidence permits single-ring conviction.
 *
 * Set deliberately at 90, which admits exactly three codes:
 *   X1  an unsigned image mapped into the protected address space
 *   X2  a foreign handle holding write access to the protected process
 *   X3  an executable-section integrity mismatch
 * Those three are proofs of tampering. X5 (foreign thread origin, 88),
 * XC (unsigned kernel image load, 86) and X6 (corpus hit, 85) sit below the line
 * on purpose: each is strong but individually circumstantial, so corroboration
 * from a second ring is required before a conviction can issue.
 */
export const STRUCTURAL_CERTAINTY_SEV = 90;

export function classify(code: EvidenceCode): CatalogEntry {
  return CATALOG[code];
}

export function rolePermitted(code: EvidenceCode, role: Role): boolean {
  return (CATALOG[code].srcMask & RING_BIT[role]) !== 0;
}
