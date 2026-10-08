/**
 * Append-only, hash-chained audit ledger.
 *
 * Verdict transitions are the only irreversible acts in this system, so each one
 * is sealed into a chain. Any retroactive edit to an earlier record invalidates
 * every subsequent hash, which the console surfaces as a chain break.
 *
 * DURABILITY. Each record is written to the `ledger_records` table as it is sealed, and
 * the table carries the same append-only triggers as the audit log, so the engine refuses
 * an UPDATE or a DELETE from any connection — a chain a later write could rewrite proves
 * nothing. The durable write happens *before* the in-memory head moves: a failed write
 * leaves the head pointing at what is on disk rather than past it, so the process never
 * seals a record whose predecessor hash nobody stored.
 *
 * RECOVERY. Constructed with a store, the ledger re-reads the whole stored chain,
 * re-verifies every link, and resumes its head and sequence from it, so a restart
 * continues the chain instead of starting a new one. If a record no longer verifies,
 * recovery ends in a BROKEN state naming the first bad sequence, and it stays broken:
 * appending after a break cannot repair it, so a tamper that happened before a restart is
 * still visible after it.
 *
 * Records are also held in a bounded in-memory tail window for cheap reads; the running
 * head is retained even after old records are evicted. A break found at boot is remembered
 * separately, because it may sit in a record the window has since evicted.
 */
import { createHash } from "node:crypto";

/**
 * Sealed record classes.
 *
 * `REQUEST` is the only kind that can be produced by an unauthenticated caller, and
 * it is deliberately the only one: `RequestIntake` seals a request only after it has
 * cleared every gate and reached the relay, so an anonymous principal cannot use the
 * public form to push genuine decision records out of the retained tail.
 */
export type LedgerKind = "VERDICT" | "CONTAIN" | "RELEASE" | "CONTROL" | "BOOT" | "REQUEST";

const KINDS: readonly string[] = ["VERDICT", "CONTAIN", "RELEASE", "CONTROL", "BOOT", "REQUEST"];

/** Narrow a `kind` read back from storage. A value from a file is not to be trusted. */
export function isLedgerKind(value: string): value is LedgerKind {
  return KINDS.includes(value);
}

export type LedgerRecord = {
  readonly seq: number;
  readonly ts: number;
  readonly kind: LedgerKind;
  /** Subject digest, or "-" for system-scoped records. */
  readonly su: string;
  /** Compact, non-descriptive detail blob. */
  readonly dt: string;
  readonly prev: string;
  readonly h: string;
};

export type LedgerTail = {
  seq: number;
  ts: number;
  kind: LedgerKind;
  su: string;
  dt: string;
  h: string;
};

export type ChainStatus = {
  readonly head: string;
  readonly length: number;
  readonly sealed: number;
  readonly broken: boolean;
  /** Sequence number of the first record whose link no longer verifies, or null. */
  readonly brokenAt: number | null;
};

/**
 * A stored record as it comes back from the data layer.
 *
 * Deliberately looser than `LedgerRecord` — `kind` is a plain string — so the storage
 * boundary does not have to trust its own file. It is narrowed with `isLedgerKind` when
 * it is turned into a record to verify.
 */
export type LedgerRow = {
  readonly seq: number;
  readonly ts: number;
  readonly kind: string;
  readonly su: string;
  readonly dt: string;
  readonly prev: string;
  readonly h: string;
};

/**
 * The storage the ledger needs. `Store` in `db.ts` satisfies this structurally, which
 * keeps the ledger free of a dependency on the data layer and lets a test hand it a
 * stub.
 */
export type LedgerStore = {
  appendLedger(record: LedgerRow): void;
  ledgerAll(): LedgerRow[];
};

/** What a recovery pass found. `null` while the ledger runs without a store. */
export type LedgerRecovery = {
  /** Records read from storage. */
  readonly records: number;
  /** True only when every stored link verified against the whole chain. */
  readonly ok: boolean;
  /** First sequence whose link no longer verifies, or null. */
  readonly at: number | null;
};

const RETAIN = 400;

/** The predecessor hash of the first record. 64 zeros, never produced by a real seal. */
const GENESIS = "0".repeat(64);

/** Exported so an external auditor (and the test suite) can replay a chain. */
export function sealRecord(prev: string, seq: number, ts: number, kind: LedgerKind, su: string, dt: string): string {
  return createHash("sha256")
    .update(`${prev}\u0000${seq}\u0000${ts}\u0000${kind}\u0000${su}\u0000${dt}`, "utf8")
    .digest("hex");
}

/**
 * Re-walk a chain of records and confirm every link. Any edit to any field, in any
 * record, invalidates that record's hash and every hash after it.
 */
export function verifyRecords(records: readonly LedgerRecord[]): { ok: boolean; at: number | null } {
  let prev: string | null = null;
  for (const r of records) {
    if (prev !== null && r.prev !== prev) return { ok: false, at: r.seq };
    if (sealRecord(r.prev, r.seq, r.ts, r.kind, r.su, r.dt) !== r.h) return { ok: false, at: r.seq };
    prev = r.h;
  }
  return { ok: true, at: null };
}

export class Ledger {
  #head = GENESIS;
  #seq = 0;
  #records: LedgerRecord[] = [];
  #sealed = 0;
  /** A break found at boot, which the retained tail may no longer contain. */
  #broken: number | null = null;
  readonly #store: LedgerStore | null;
  /** Outcome of the boot verification pass, or null while running without a store. */
  readonly recovery: LedgerRecovery | null;

  constructor(options: { readonly store?: LedgerStore } = {}) {
    this.#store = options.store ?? null;
    this.recovery = this.#store === null ? null : this.#recover(this.#store);
  }

  /**
   * Re-read and re-verify the stored chain, then resume from its last record.
   *
   * The whole chain is read rather than just the window, because verification is only
   * meaningful from genesis: a window that starts mid-chain has no predecessor to check
   * its first record against. A storage error is not swallowed — a ledger that cannot
   * read its own chain must not come up pretending the chain is empty, because that
   * would silently restart the sequence and orphan every sealed record.
   */
  #recover(store: LedgerStore): LedgerRecovery {
    const rows = store.ledgerAll();
    if (rows.length === 0) return { records: 0, ok: true, at: null };

    const records: LedgerRecord[] = [];
    let ok = true;
    let at: number | null = null;
    for (const row of rows) {
      // A kind the schema does not model is a rewritten row before the hash is even
      // checked, and it is refused here so the walk below can keep its types.
      if (!isLedgerKind(row.kind)) {
        ok = false;
        at = row.seq;
        break;
      }
      records.push({ seq: row.seq, ts: row.ts, kind: row.kind, su: row.su, dt: row.dt, prev: row.prev, h: row.h });
    }
    if (ok) {
      const verdict = verifyRecords(records);
      ({ ok, at } = verdict);
    }

    const last = rows[rows.length - 1];
    if (last !== undefined) {
      this.#seq = last.seq;
      this.#head = last.h;
      this.#sealed = rows.length;
      this.#broken = ok ? null : at;
      // On a broken chain this is best effort: the tail is hydrated from whatever still
      // verified, so the console shows what could be read rather than nothing at all.
      this.#records = records.slice(Math.max(0, records.length - RETAIN));
    }
    return { records: rows.length, ok, at };
  }

  append(kind: LedgerKind, su: string, dt: string, now: number): LedgerRecord {
    const seq = this.#seq + 1;
    const prev = this.#head;
    const h = sealRecord(prev, seq, now, kind, su, dt);
    const record: LedgerRecord = { seq, ts: now, kind, su, dt, prev, h };
    // Durable write first, in-memory head second. If the write throws, this record is
    // not sealed anywhere and the head does not advance past it.
    if (this.#store !== null) {
      this.#store.appendLedger({ seq, ts: now, kind, su, dt, prev, h });
    }
    this.#seq = seq;
    this.#head = h;
    this.#records.push(record);
    if (this.#records.length > RETAIN) this.#records.splice(0, this.#records.length - RETAIN);
    this.#sealed += 1;
    return record;
  }

  get head(): string {
    return this.#head;
  }

  get length(): number {
    return this.#seq;
  }

  status(): ChainStatus {
    const verdict = this.verify();
    return {
      head: this.#head,
      length: this.#seq,
      sealed: this.#sealed,
      broken: !verdict.ok,
      brokenAt: verdict.ok ? null : verdict.at,
    };
  }

  tail(limit: number): LedgerTail[] {
    const n = Math.max(0, Math.min(limit, this.#records.length));
    const slice = this.#records.slice(this.#records.length - n);
    return slice.map((r) => ({ seq: r.seq, ts: r.ts, kind: r.kind, su: r.su, dt: r.dt, h: r.h }));
  }

  /**
   * Re-walk the retained window and confirm every link.
   *
   * A break found at boot is reported first, because it may sit in a record the window
   * has since evicted: without that, the tail would verify cleanly over a chain known to
   * be broken, which is the one answer this method must never give.
   */
  verify(): { ok: boolean; at: number | null } {
    if (this.#broken !== null) return { ok: false, at: this.#broken };
    return verifyRecords(this.#records);
  }

  /** Copy of the retained records, for external audit or test inspection. */
  recordsView(): readonly LedgerRecord[] {
    return this.#records.map((r) => ({ ...r }));
  }
}
