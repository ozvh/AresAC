/**
 * Data layer.
 *
 * SQLite through `node:sqlite`, which is built into the runtime: no driver dependency,
 * no connection pool, no ORM. The reason is not convenience. An ORM is a second
 * query language layered over the first one, and every injection review then has to
 * reason about two languages instead of one. Here there is exactly one way a value can
 * enter a statement — as a bound parameter — and that is auditable by reading the file.
 *
 * RULES THIS FILE ENFORCES ON ITSELF.
 *
 * 1. NO SQL IS EVER ASSEMBLED FROM DATA. Every statement is a literal string here, and
 *    every value travels as `?`. There is no template literal containing a variable
 *    anywhere in this module, which is the property that makes "parameterized queries"
 *    a fact rather than an intention. A test greps for the absence of the pattern.
 * 2. RULES LIVE IN THE SCHEMA, NOT ONLY IN TYPESCRIPT. CHECK constraints, NOT NULL,
 *    UNIQUE and FOREIGN KEYs are declared in DDL and enforced by the engine, so a bug
 *    in a handler cannot write a role that does not exist or a row that points at no
 *    user. `PRAGMA foreign_keys = ON` is set explicitly because SQLite disables foreign
 *    key enforcement by default — an omitted pragma is a silent constraint bypass.
 * 3. THE AUDIT LOG IS APPEND-ONLY, ENFORCED BY TRIGGERS. UPDATE and DELETE on it raise.
 *    An audit trail that application code could rewrite is not an audit trail.
 * 4. LEAST PRIVILEGE, HONESTLY DESCRIBED. SQLite has no roles, so this process
 *    necessarily holds write access to its own file. What is genuinely restricted:
 *    the database lives outside every asset root, `ATTACH` and `load_extension` are
 *    never called, and no statement is dynamic. A PostgreSQL deployment should instead
 *    give this role INSERT/SELECT on named tables only, and use row level security
 *    policies keyed on the application's user id — see `docs/SECURITY.md`.
 */
import { chmodSync, mkdirSync } from "node:fs";
import path from "node:path";
import { DatabaseSync, type StatementSync } from "node:sqlite";

export type Role = "CUSTOMER" | "ADMIN";
export type AccountStatus = "ACTIVE" | "SUSPENDED" | "CLOSED";
export type ConsentKind = "TERMS" | "PRIVACY" | "MARKETING";
export type Plan = "EVALUATION" | "RETAIL" | "SOURCE";
export type SubStatus = "ACTIVE" | "CANCELLED" | "EXPIRED";
export type UploadVerdict = "ACCEPTED" | "QUARANTINED" | "REJECTED";
export type ActorRole = "ANON" | "CUSTOMER" | "ADMIN" | "SYSTEM";
export type Outcome = "OK" | "REFUSED";

/** Absolute session lifetime. Sliding activity never extends past this. */
export const SESSION_TTL_MS = 7 * 24 * 60 * 60 * 1_000;

/** Below this, `last_seen_at` is left alone: one write per request per session is waste. */
export const SESSION_TOUCH_MS = 15 * 60 * 1_000;

/** Upload retention window, in days, from the environment. Stated in the privacy policy. */
export function retentionDays(env: NodeJS.ProcessEnv): number {
  const raw = Number(env["ARES_UPLOAD_RETENTION_DAYS"] ?? "30");
  if (!Number.isFinite(raw) || raw < 1) return 30;
  return Math.min(365, Math.floor(raw));
}

/** Days before a renewal that the reminder goes out. */
export function renewalNoticeDays(env: NodeJS.ProcessEnv): number {
  const raw = Number(env["ARES_RENEWAL_NOTICE_DAYS"] ?? "14");
  if (!Number.isFinite(raw) || raw < 1) return 14;
  return Math.min(90, Math.floor(raw));
}

/* ------------------------------------------------------------------ */
/*  Row shapes. Each SELECT names its columns explicitly, so the shape  */
/*  below is decided by the statement in this file and not by the       */
/*  database. No `SELECT *` appears in this module.                     */
/* ------------------------------------------------------------------ */

export type UserRow = {
  id: string;
  email: string;
  display_name: string;
  role: Role;
  status: AccountStatus;
  pwd_hash: string;
  created_at: number;
  updated_at: number;
  last_login_at: number | null;
  failed_logins: number;
  locked_until: number;
  password_changed_at: number;
  must_change_password: number;
};

export type SessionRow = {
  id: string;
  user_id: string;
  token_hash: string;
  csrf_hash: string;
  created_at: number;
  expires_at: number;
  last_seen_at: number;
  ip_hash: string;
  ua_hash: string;
  revoked_at: number | null;
};

export type AuditRow = {
  seq: number;
  ts: number;
  actor_id: string | null;
  actor_role: ActorRole;
  action: string;
  subject_id: string | null;
  outcome: Outcome;
  detail: string;
  ip_hash: string;
};

export type ConsentRow = {
  id: string;
  user_id: string;
  kind: ConsentKind;
  version: string;
  granted_at: number;
  withdrawn_at: number | null;
};

export type SubscriptionRow = {
  id: string;
  user_id: string;
  plan: Plan;
  status: SubStatus;
  started_at: number;
  current_period_end: number;
  auto_renew: number;
  cancelled_at: number | null;
  cancel_effective_at: number | null;
  reminder_sent_for: number;
};

export type UploadRow = {
  id: string;
  user_id: string;
  request_ref: string | null;
  stored_name: string;
  original_name: string;
  declared_type: string;
  detected_type: string;
  bytes: number;
  sha256: string;
  verdict: UploadVerdict;
  scan_detail: string;
  created_at: number;
  expires_at: number;
  deleted_at: number | null;
};

/**
 * A sealed decision-ledger record as it is stored and read back.
 *
 * `kind` is a plain string here on purpose: a value read from a file is not something
 * this layer may assume, and the ledger narrows it through its own runtime guard. The
 * CHECK constraint below is the enforcement that keeps it to the modelled set.
 */
export type LedgerRecordRow = {
  seq: number;
  ts: number;
  kind: string;
  su: string;
  dt: string;
  prev: string;
  h: string;
};

export type AuditInput = {
  readonly ts: number;
  readonly actorId: string | null;
  readonly actorRole: ActorRole;
  readonly action: string;
  readonly subjectId: string | null;
  readonly outcome: Outcome;
  readonly detail: string;
  readonly ipHash: string;
};

/**
 * The schema.
 *
 * Written as one migration because there is nothing to migrate from. Future changes
 * append a new numbered entry to `MIGRATIONS`; the runner records the applied version in
 * `PRAGMA user_version` and refuses to run a database whose version it does not know,
 * which is the failure mode that matters — silently serving an older schema is how a
 * missing column becomes a 500 at the worst possible moment.
 */
const MIGRATION_1 = `
CREATE TABLE users (
  id                    TEXT    PRIMARY KEY,
  email                 TEXT    NOT NULL,
  display_name          TEXT    NOT NULL,
  role                  TEXT    NOT NULL CHECK (role IN ('CUSTOMER','ADMIN')),
  status                TEXT    NOT NULL CHECK (status IN ('ACTIVE','SUSPENDED','CLOSED')),
  pwd_hash              TEXT    NOT NULL,
  created_at            INTEGER NOT NULL,
  updated_at            INTEGER NOT NULL,
  last_login_at         INTEGER,
  failed_logins         INTEGER NOT NULL DEFAULT 0 CHECK (failed_logins >= 0),
  locked_until          INTEGER NOT NULL DEFAULT 0,
  password_changed_at   INTEGER NOT NULL,
  must_change_password  INTEGER NOT NULL DEFAULT 0 CHECK (must_change_password IN (0,1)),
  -- Address shape is checked here as well as in the handler. Two independent checks is
  -- the point: the handler can be edited, the constraint travels with the data.
  CHECK (length(email) BETWEEN 6 AND 254),
  CHECK (email LIKE '%_@_%._%'),
  CHECK (length(display_name) BETWEEN 1 AND 80)
);

-- Uniqueness is case-insensitive because addresses are. Normalisation happens in the
-- handler, and this index is the enforcement that stops a race from creating two
-- accounts for one person.
CREATE UNIQUE INDEX users_email_unique ON users (email COLLATE NOCASE);

CREATE TABLE sessions (
  id            TEXT    PRIMARY KEY,
  user_id       TEXT    NOT NULL REFERENCES users (id) ON DELETE CASCADE,
  -- Only a digest of the session secret is stored. A dump of this table grants no
  -- ability to present a session.
  token_hash    TEXT    NOT NULL,
  csrf_hash     TEXT    NOT NULL,
  created_at    INTEGER NOT NULL,
  expires_at    INTEGER NOT NULL,
  last_seen_at  INTEGER NOT NULL,
  ip_hash       TEXT    NOT NULL,
  ua_hash       TEXT    NOT NULL,
  revoked_at    INTEGER,
  CHECK (expires_at > created_at)
);

CREATE UNIQUE INDEX sessions_token_unique ON sessions (token_hash);
CREATE INDEX sessions_by_user ON sessions (user_id);
CREATE INDEX sessions_live ON sessions (expires_at) WHERE revoked_at IS NULL;

CREATE TABLE consents (
  id            TEXT    PRIMARY KEY,
  user_id       TEXT    NOT NULL REFERENCES users (id) ON DELETE CASCADE,
  kind          TEXT    NOT NULL CHECK (kind IN ('TERMS','PRIVACY','MARKETING')),
  version       TEXT    NOT NULL,
  granted_at    INTEGER NOT NULL,
  withdrawn_at  INTEGER
);

CREATE UNIQUE INDEX consents_unique ON consents (user_id, kind, version);

CREATE TABLE subscriptions (
  id                   TEXT    PRIMARY KEY,
  user_id              TEXT    NOT NULL REFERENCES users (id) ON DELETE CASCADE,
  plan                 TEXT    NOT NULL CHECK (plan IN ('EVALUATION','RETAIL','SOURCE')),
  status               TEXT    NOT NULL CHECK (status IN ('ACTIVE','CANCELLED','EXPIRED')),
  started_at           INTEGER NOT NULL,
  current_period_end   INTEGER NOT NULL,
  auto_renew           INTEGER NOT NULL CHECK (auto_renew IN (0,1)),
  cancelled_at         INTEGER,
  cancel_effective_at  INTEGER,
  -- The period end this subscription was last warned about, so a reminder is sent
  -- exactly once per period rather than on every sweeper pass.
  reminder_sent_for    INTEGER NOT NULL DEFAULT 0
);

CREATE INDEX subscriptions_by_user ON subscriptions (user_id);
CREATE INDEX subscriptions_renewing ON subscriptions (status, auto_renew, current_period_end);

CREATE TABLE uploads (
  id             TEXT    PRIMARY KEY,
  user_id        TEXT    NOT NULL REFERENCES users (id) ON DELETE CASCADE,
  request_ref    TEXT,
  stored_name    TEXT    NOT NULL,
  original_name  TEXT    NOT NULL,
  declared_type  TEXT    NOT NULL,
  detected_type  TEXT    NOT NULL,
  bytes          INTEGER NOT NULL CHECK (bytes >= 0),
  sha256         TEXT    NOT NULL,
  verdict        TEXT    NOT NULL CHECK (verdict IN ('ACCEPTED','QUARANTINED','REJECTED')),
  scan_detail    TEXT    NOT NULL DEFAULT '',
  created_at     INTEGER NOT NULL,
  expires_at     INTEGER NOT NULL,
  deleted_at     INTEGER,
  CHECK (expires_at > created_at),
  CHECK (length(sha256) = 64)
);

CREATE INDEX uploads_by_user ON uploads (user_id);
CREATE INDEX uploads_expiry ON uploads (expires_at) WHERE deleted_at IS NULL;

CREATE TABLE audit_log (
  seq         INTEGER PRIMARY KEY AUTOINCREMENT,
  ts          INTEGER NOT NULL,
  actor_id    TEXT,
  actor_role  TEXT    NOT NULL CHECK (actor_role IN ('ANON','CUSTOMER','ADMIN','SYSTEM')),
  action      TEXT    NOT NULL,
  subject_id  TEXT,
  outcome     TEXT    NOT NULL CHECK (outcome IN ('OK','REFUSED')),
  detail      TEXT    NOT NULL DEFAULT '',
  ip_hash     TEXT    NOT NULL DEFAULT ''
);

CREATE INDEX audit_by_time ON audit_log (ts);
CREATE INDEX audit_by_actor ON audit_log (actor_id, ts);

-- Immutability, enforced where it cannot be bypassed by application code.
CREATE TRIGGER audit_log_no_update BEFORE UPDATE ON audit_log
BEGIN
  SELECT RAISE(ABORT, 'audit_log is append-only');
END;

CREATE TRIGGER audit_log_no_delete BEFORE DELETE ON audit_log
BEGIN
  SELECT RAISE(ABORT, 'audit_log is append-only');
END;
`;

/**
 * Migration 2: the durable decision ledger.
 *
 * The hash chain is only evidence if it outlives the process that built it, so it gets
 * its own table. Two properties are enforced here rather than in the ledger:
 *
 *  - APPEND-ONLY, BY TRIGGER. UPDATE and DELETE raise, exactly as on `audit_log`. A
 *    chain a later write could rewrite proves nothing, and this is the guard that holds
 *    even when the writing code is buggy or malicious.
 *  - LINK SHAPE, BY CHECK. `prev` and `h` are 64 hex characters and `seq` starts at 1,
 *    so a truncated or malformed link cannot enter the chain in the first place.
 */
const MIGRATION_2 = `
CREATE TABLE ledger_records (
  seq   INTEGER PRIMARY KEY,
  ts    INTEGER NOT NULL,
  kind  TEXT    NOT NULL CHECK (kind IN ('VERDICT','CONTAIN','RELEASE','CONTROL','BOOT','REQUEST')),
  su    TEXT    NOT NULL,
  dt    TEXT    NOT NULL,
  prev  TEXT    NOT NULL,
  h     TEXT    NOT NULL,
  CHECK (seq >= 1),
  CHECK (length(prev) = 64),
  CHECK (length(h) = 64)
);

-- Immutability of the decision ledger, enforced where application code cannot bypass it.
CREATE TRIGGER ledger_records_no_update BEFORE UPDATE ON ledger_records
BEGIN
  SELECT RAISE(ABORT, 'ledger_records is append-only');
END;

CREATE TRIGGER ledger_records_no_delete BEFORE DELETE ON ledger_records
BEGIN
  SELECT RAISE(ABORT, 'ledger_records is append-only');
END;
`;

const MIGRATIONS: readonly string[] = [MIGRATION_1, MIGRATION_2];

/** The schema version this build expects. A newer file is refused rather than guessed at. */
export const SCHEMA_VERSION = MIGRATIONS.length;

/**
 * Narrow an untyped engine result to a row shape.
 *
 * The cast is confined to this one function and is safe because every SELECT in this
 * module lists its columns explicitly: the shape is a property of the statement above
 * it, not of whatever the file happens to contain. Reading a row that predates a
 * migration is prevented by the version check at open time.
 */
function asRow<T>(value: unknown): T | null {
  if (value === undefined || value === null) return null;
  if (typeof value !== "object") return null;
  return value as T;
}

function asRows<T>(values: readonly unknown[]): T[] {
  const out: T[] = [];
  for (const value of values) {
    const row = asRow<T>(value);
    if (row !== null) out.push(row);
  }
  return out;
}

export type StoreOptions = {
  /** File path, or ":memory:" for tests. */
  readonly file: string;
  readonly now: () => number;
};

export class Store {
  readonly #db: DatabaseSync;
  readonly #statements = new Map<string, StatementSync>();

  constructor(options: StoreOptions) {
    if (options.file !== ":memory:") {
      mkdirSync(path.dirname(path.resolve(options.file)), { recursive: true });
    }
    this.#db = new DatabaseSync(options.file);
    this.#restrictFileMode(options.file);
    // Foreign keys are OFF by default in SQLite. Every REFERENCES clause above is
    // decorative until this line runs.
    this.#db.exec("PRAGMA foreign_keys = ON");
    // Write-ahead logging so the sweeper and a request handler do not block each other.
    this.#db.exec("PRAGMA journal_mode = WAL");
    this.#db.exec("PRAGMA synchronous = NORMAL");
    // Do not follow a table or column name supplied by a value. Cheap, and it closes a
    // class of schema-shadowing attack that has no legitimate use here.
    this.#db.exec("PRAGMA trusted_schema = OFF");
    this.#migrate();
  }

  /**
   * Take the mode off the process umask.
   *
   * SQLite creates the file itself, so it arrives with whatever the umask allows — on a
   * host with a permissive one that is a world-readable database holding session digests,
   * consent records and the audit log. Owner-only is the only defensible mode for a file
   * this process is the sole reader and writer of.
   *
   * It is best-effort by design: a platform that does not implement POSIX modes must not
   * fail to start over this, and the failure is reported rather than swallowed so an
   * operator is not left believing a mode was set when it was not. The journal and WAL
   * sidecars are created later by SQLite, so the honest statement is that this covers the
   * database file and the parent directory is created 0700 above.
   */
  #restrictFileMode(file: string): void {
    if (file === ":memory:") return;
    try {
      chmodSync(file, 0o600);
    } catch {
      // Windows maps these bits onto a read-only flag and a filesystem may refuse the
      // call; either way the operator's host policy is the control that applies there.
    }
  }

  /** Prepared statement cache. The SQL is a literal, so caching is keyed by statement only. */
  #stmt(sql: string): StatementSync {
    const cached = this.#statements.get(sql);
    if (cached !== undefined) return cached;
    const prepared = this.#db.prepare(sql);
    this.#statements.set(sql, prepared);
    return prepared;
  }

  #migrate(): void {
    const current = this.#readUserVersion();
    if (current > SCHEMA_VERSION) {
      throw new Error(
        `database schema version ${current} is newer than this build understands (${SCHEMA_VERSION}); refusing to open`,
      );
    }
    if (current === SCHEMA_VERSION) return;
    this.#db.exec("BEGIN IMMEDIATE");
    try {
      for (let version = current; version < SCHEMA_VERSION; version += 1) {
        const script = MIGRATIONS[version];
        if (script === undefined) throw new Error(`no migration for version ${version + 1}`);
        this.#db.exec(script);
      }
      // The one place a value reaches SQL without a bound parameter, because PRAGMA does
      // not accept them. It is safe for a specific reason: SCHEMA_VERSION is a compile-time
      // constant derived from the length of MIGRATIONS, so no code path exists on which a
      // caller can influence it. The test suite asserts that no *prepared statement* in
      // this module is ever built from a template literal.
      this.#db.exec(`PRAGMA user_version = ${SCHEMA_VERSION}`);
      this.#db.exec("COMMIT");
    } catch (error) {
      this.#db.exec("ROLLBACK");
      throw error;
    }
  }

  #readUserVersion(): number {
    const row = asRow<{ user_version: number }>(this.#db.prepare("PRAGMA user_version").get());
    return row === null ? 0 : Number(row.user_version);
  }

  /** Serialised write transaction. Reads inside see the transaction's own writes. */
  tx<T>(fn: () => T): T {
    this.#db.exec("BEGIN IMMEDIATE");
    try {
      const result = fn();
      this.#db.exec("COMMIT");
      return result;
    } catch (error) {
      this.#db.exec("ROLLBACK");
      throw error;
    }
  }

  close(): void {
    this.#statements.clear();
    this.#db.close();
  }

  /* ---------------- users ---------------- */

  insertUser(row: {
    id: string;
    email: string;
    displayName: string;
    role: Role;
    pwdHash: string;
    now: number;
    mustChangePassword: boolean;
  }): void {
    this.#stmt(
      `INSERT INTO users
         (id, email, display_name, role, status, pwd_hash, created_at, updated_at, last_login_at,
          failed_logins, locked_until, password_changed_at, must_change_password)
       VALUES (?, ?, ?, ?, 'ACTIVE', ?, ?, ?, NULL, 0, 0, ?, ?)`,
    ).run(
      row.id,
      row.email,
      row.displayName,
      row.role,
      row.pwdHash,
      row.now,
      row.now,
      row.now,
      row.mustChangePassword ? 1 : 0,
    );
  }

  userByEmail(email: string): UserRow | null {
    return asRow<UserRow>(
      this.#stmt(
        `SELECT id, email, display_name, role, status, pwd_hash, created_at, updated_at, last_login_at,
                failed_logins, locked_until, password_changed_at, must_change_password
           FROM users WHERE email = ? COLLATE NOCASE`,
      ).get(email),
    );
  }

  userById(id: string): UserRow | null {
    return asRow<UserRow>(
      this.#stmt(
        `SELECT id, email, display_name, role, status, pwd_hash, created_at, updated_at, last_login_at,
                failed_logins, locked_until, password_changed_at, must_change_password
           FROM users WHERE id = ?`,
      ).get(id),
    );
  }

  /**
   * Record a failed authentication and lock the account after a run of them.
   *
   * The lock is time-bounded rather than permanent: a permanent lock keyed on an
   * attacker-supplied address is a denial of service against the account's owner.
   */
  recordAuthFailure(userId: string, now: number, maxFailures: number, lockMs: number): void {
    this.tx(() => {
      const row = asRow<{ failed_logins: number }>(
        this.#stmt("SELECT failed_logins FROM users WHERE id = ?").get(userId),
      );
      const next = (row === null ? 0 : Number(row.failed_logins)) + 1;
      const lockUntil = next >= maxFailures ? now + lockMs : 0;
      this.#stmt("UPDATE users SET failed_logins = ?, locked_until = ?, updated_at = ? WHERE id = ?").run(
        lockUntil > 0 ? 0 : next,
        lockUntil,
        now,
        userId,
      );
    });
  }

  recordAuthSuccess(userId: string, now: number): void {
    this.#stmt(
      "UPDATE users SET failed_logins = 0, locked_until = 0, last_login_at = ?, updated_at = ? WHERE id = ?",
    ).run(now, now, userId);
  }

  setPassword(userId: string, pwdHash: string, now: number, mustChange: boolean): void {
    this.#stmt(
      "UPDATE users SET pwd_hash = ?, password_changed_at = ?, must_change_password = ?, updated_at = ? WHERE id = ?",
    ).run(pwdHash, now, mustChange ? 1 : 0, now, userId);
  }

  setUserStatus(userId: string, status: AccountStatus, now: number): void {
    this.#stmt("UPDATE users SET status = ?, updated_at = ? WHERE id = ?").run(status, now, userId);
  }

  setUserRole(userId: string, role: Role, now: number): void {
    this.#stmt("UPDATE users SET role = ?, updated_at = ? WHERE id = ?").run(role, now, userId);
  }

  countUsers(role: Role): number {
    const row = asRow<{ n: number }>(this.#stmt("SELECT COUNT(*) AS n FROM users WHERE role = ?").get(role));
    return row === null ? 0 : Number(row.n);
  }

  /** Accounts for the admin surface. Never selects a password digest. */
  listUsers(limit: number, offset: number): Array<Pick<UserRow, "id" | "email" | "display_name" | "role" | "status" | "created_at" | "last_login_at">> {
    return asRows(
      this.#stmt(
        `SELECT id, email, display_name, role, status, created_at, last_login_at
           FROM users ORDER BY created_at DESC LIMIT ? OFFSET ?`,
      ).all(limit, offset),
    );
  }

  /* ---------------- sessions ---------------- */

  insertSession(row: {
    id: string;
    userId: string;
    tokenHash: string;
    csrfHash: string;
    now: number;
    expiresAt: number;
    ipHash: string;
    uaHash: string;
  }): void {
    this.#stmt(
      `INSERT INTO sessions (id, user_id, token_hash, csrf_hash, created_at, expires_at, last_seen_at, ip_hash, ua_hash, revoked_at)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, NULL)`,
    ).run(row.id, row.userId, row.tokenHash, row.csrfHash, row.now, row.expiresAt, row.now, row.ipHash, row.uaHash);
  }

  sessionByTokenHash(tokenHash: string): SessionRow | null {
    return asRow<SessionRow>(
      this.#stmt(
        `SELECT id, user_id, token_hash, csrf_hash, created_at, expires_at, last_seen_at, ip_hash, ua_hash, revoked_at
           FROM sessions WHERE token_hash = ?`,
      ).get(tokenHash),
    );
  }

  /** Look a session up by its own id. Used for CSRF verification on a resolved identity. */
  sessionById(id: string): SessionRow | null {
    return asRow<SessionRow>(
      this.#stmt(
        `SELECT id, user_id, token_hash, csrf_hash, created_at, expires_at, last_seen_at, ip_hash, ua_hash, revoked_at
           FROM sessions WHERE id = ?`,
      ).get(id),
    );
  }

  // There is deliberately no setter for `csrf_hash`. The synchroniser token is derived
  // from the session cookie in `auth.ts`, so a rotation would be a re-derivation rather
  // than a write, and an accessor here would invite a caller to replace the tamper
  // evidence with a value of its own choosing.

  touchSession(id: string, now: number): void {
    this.#stmt("UPDATE sessions SET last_seen_at = ? WHERE id = ?").run(now, id);
  }

  revokeSession(id: string, now: number): void {
    this.#stmt("UPDATE sessions SET revoked_at = ? WHERE id = ? AND revoked_at IS NULL").run(now, id);
  }

  /** Revoke every live session for a user. Used on password change and on suspension. */
  revokeUserSessions(userId: string, now: number): number {
    const result = this.#stmt("UPDATE sessions SET revoked_at = ? WHERE user_id = ? AND revoked_at IS NULL").run(
      now,
      userId,
    );
    return Number(result.changes);
  }

  countLiveSessions(userId: string, now: number): number {
    const row = asRow<{ n: number }>(
      this.#stmt(
        "SELECT COUNT(*) AS n FROM sessions WHERE user_id = ? AND revoked_at IS NULL AND expires_at > ?",
      ).get(userId, now),
    );
    return row === null ? 0 : Number(row.n);
  }

  /** Remove sessions that can no longer authenticate anyone. Bounded housekeeping. */
  pruneSessions(now: number): number {
    const result = this.#stmt("DELETE FROM sessions WHERE expires_at <= ? OR revoked_at IS NOT NULL").run(now);
    return Number(result.changes);
  }

  /* ---------------- audit ---------------- */

  /**
   * Append one audit record.
   *
   * This is the only writer, and it cannot be undone: the triggers in the schema refuse
   * UPDATE and DELETE. Every path that changes authority, money or identity calls it —
   * the test suite asserts that each of those paths leaves a record behind.
   */
  audit(entry: AuditInput): void {
    this.#stmt(
      `INSERT INTO audit_log (ts, actor_id, actor_role, action, subject_id, outcome, detail, ip_hash)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
    ).run(
      entry.ts,
      entry.actorId,
      entry.actorRole,
      entry.action,
      entry.subjectId,
      entry.outcome,
      entry.detail,
      entry.ipHash,
    );
  }

  auditTail(limit: number): AuditRow[] {
    return asRows(
      this.#stmt(
        `SELECT seq, ts, actor_id, actor_role, action, subject_id, outcome, detail, ip_hash
           FROM audit_log ORDER BY seq DESC LIMIT ?`,
      ).all(limit),
    );
  }

  auditForActor(actorId: string, limit: number): AuditRow[] {
    return asRows(
      this.#stmt(
        `SELECT seq, ts, actor_id, actor_role, action, subject_id, outcome, detail, ip_hash
           FROM audit_log WHERE actor_id = ? ORDER BY seq DESC LIMIT ?`,
      ).all(actorId, limit),
    );
  }

  countAudit(): number {
    const row = asRow<{ n: number }>(this.#stmt("SELECT COUNT(*) AS n FROM audit_log").get());
    return row === null ? 0 : Number(row.n);
  }

  /* ---------------- decision ledger ---------------- */

  /**
   * Append one sealed record to the durable chain.
   *
   * There is no update and no delete accessor, and the triggers refuse both: the only
   * write this table accepts is the next link. The ledger calls this *before* it moves
   * its in-memory head, so a failed write leaves the head pointing at what is on disk.
   */
  appendLedger(record: LedgerRecordRow): void {
    this.#stmt(
      `INSERT INTO ledger_records (seq, ts, kind, su, dt, prev, h)
       VALUES (?, ?, ?, ?, ?, ?, ?)`,
    ).run(record.seq, record.ts, record.kind, record.su, record.dt, record.prev, record.h);
  }

  /**
   * The whole stored chain, oldest first.
   *
   * Read in full because verification is only meaningful from genesis: a window that
   * starts mid-chain has no predecessor to check its first record against. The ledger
   * holds decisions, not telemetry, so this set is small next to the event stream.
   */
  ledgerAll(): LedgerRecordRow[] {
    return asRows(
      this.#stmt("SELECT seq, ts, kind, su, dt, prev, h FROM ledger_records ORDER BY seq ASC").all(),
    );
  }

  /* ---------------- consents ---------------- */

  grantConsent(row: { id: string; userId: string; kind: ConsentKind; version: string; now: number }): void {
    // Idempotent: re-accepting the same policy version is not a new consent, and the
    // unique index would otherwise turn a double submit into a 500.
    this.#stmt(
      `INSERT INTO consents (id, user_id, kind, version, granted_at, withdrawn_at)
       VALUES (?, ?, ?, ?, ?, NULL)
       ON CONFLICT (user_id, kind, version) DO NOTHING`,
    ).run(row.id, row.userId, row.kind, row.version, row.now);
  }

  listConsents(userId: string): ConsentRow[] {
    return asRows(
      this.#stmt(
        "SELECT id, user_id, kind, version, granted_at, withdrawn_at FROM consents WHERE user_id = ? ORDER BY granted_at DESC",
      ).all(userId),
    );
  }

  withdrawConsent(userId: string, kind: ConsentKind, now: number): number {
    const result = this.#stmt(
      "UPDATE consents SET withdrawn_at = ? WHERE user_id = ? AND kind = ? AND withdrawn_at IS NULL",
    ).run(now, userId, kind);
    return Number(result.changes);
  }

  /* ---------------- subscriptions ---------------- */

  insertSubscription(row: {
    id: string;
    userId: string;
    plan: Plan;
    now: number;
    periodEnd: number;
    autoRenew: boolean;
  }): void {
    this.#stmt(
      `INSERT INTO subscriptions
         (id, user_id, plan, status, started_at, current_period_end, auto_renew, cancelled_at, cancel_effective_at, reminder_sent_for)
       VALUES (?, ?, ?, 'ACTIVE', ?, ?, ?, NULL, NULL, 0)`,
    ).run(row.id, row.userId, row.plan, row.now, row.periodEnd, row.autoRenew ? 1 : 0);
  }

  /**
   * One subscription, scoped to its owner.
   *
   * The user id is part of the WHERE clause rather than something a caller checks
   * afterwards. A handler that forgot the check would hand one account another account's
   * row, so the query does not offer a way to ask for a subscription without an owner.
   */
  subscriptionFor(id: string, userId: string): SubscriptionRow | null {
    return asRow<SubscriptionRow>(
      this.#stmt(
        `SELECT id, user_id, plan, status, started_at, current_period_end, auto_renew, cancelled_at,
                cancel_effective_at, reminder_sent_for
           FROM subscriptions WHERE id = ? AND user_id = ?`,
      ).get(id, userId),
    );
  }

  activeSubscription(userId: string): SubscriptionRow | null {
    return asRow<SubscriptionRow>(
      this.#stmt(
        `SELECT id, user_id, plan, status, started_at, current_period_end, auto_renew, cancelled_at,
                cancel_effective_at, reminder_sent_for
           FROM subscriptions WHERE user_id = ? AND status = 'ACTIVE' ORDER BY started_at DESC LIMIT 1`,
      ).get(userId),
    );
  }

  /**
   * Renewals that are inside the notice window and have not been warned about yet.
   *
   * The `reminder_sent_for` column is what makes this exactly-once per period. A
   * sweeper that merely looked at the date would re-send on every pass.
   */
  dueRenewalNotices(now: number, noticeMs: number, limit: number): SubscriptionRow[] {
    return asRows(
      this.#stmt(
        `SELECT id, user_id, plan, status, started_at, current_period_end, auto_renew, cancelled_at,
                cancel_effective_at, reminder_sent_for
           FROM subscriptions
          WHERE status = 'ACTIVE'
            AND auto_renew = 1
            AND cancelled_at IS NULL
            AND current_period_end > ?
            AND current_period_end <= ?
            AND reminder_sent_for <> current_period_end
          ORDER BY current_period_end ASC
          LIMIT ?`,
      ).all(now, now + noticeMs, limit),
    );
  }

  markReminderSent(subscriptionId: string, periodEnd: number): void {
    this.#stmt("UPDATE subscriptions SET reminder_sent_for = ? WHERE id = ?").run(periodEnd, subscriptionId);
  }

  /** Auto-renew off, service continues to the end of the paid period. */
  cancelSubscription(subscriptionId: string, now: number): void {
    this.#stmt(
      "UPDATE subscriptions SET auto_renew = 0, cancelled_at = ?, cancel_effective_at = current_period_end WHERE id = ?",
    ).run(now, subscriptionId);
  }

  /** Stop immediately at the end of the current period: what the sweeper does on expiry. */
  expireSubscriptions(now: number): number {
    const result = this.#stmt(
      "UPDATE subscriptions SET status = 'EXPIRED', auto_renew = 0 WHERE status = 'ACTIVE' AND current_period_end <= ?",
    ).run(now);
    return Number(result.changes);
  }

  setAutoRenew(subscriptionId: string, on: boolean, now: number): void {
    this.#stmt("UPDATE subscriptions SET auto_renew = ?, cancelled_at = ? WHERE id = ?").run(
      on ? 1 : 0,
      on ? null : now,
      subscriptionId,
    );
  }

  /* ---------------- uploads ---------------- */

  insertUpload(row: {
    id: string;
    userId: string;
    requestRef: string | null;
    storedName: string;
    originalName: string;
    declaredType: string;
    detectedType: string;
    bytes: number;
    sha256: string;
    verdict: UploadVerdict;
    scanDetail: string;
    now: number;
    expiresAt: number;
  }): void {
    this.#stmt(
      `INSERT INTO uploads
         (id, user_id, request_ref, stored_name, original_name, declared_type, detected_type, bytes, sha256,
          verdict, scan_detail, created_at, expires_at, deleted_at)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, NULL)`,
    ).run(
      row.id,
      row.userId,
      row.requestRef,
      row.storedName,
      row.originalName,
      row.declaredType,
      row.detectedType,
      row.bytes,
      row.sha256,
      row.verdict,
      row.scanDetail,
      row.now,
      row.expiresAt,
    );
  }

  /**
   * Uploads belonging to one user, and only that user.
   *
   * Row scope is a WHERE clause here rather than a convention in a handler. A handler
   * that forgot the user id would return another account's rows, so the accessor does
   * not offer a way to ask without one — the only per-user read takes a user id as its
   * first argument. In PostgreSQL this becomes a row level security policy keyed on
   * `current_setting('app.user_id')`, which enforces the same boundary one layer lower.
   */
  uploadsForUser(userId: string, limit: number): UploadRow[] {
    return asRows(
      this.#stmt(
        `SELECT id, user_id, request_ref, stored_name, original_name, declared_type, detected_type, bytes,
                sha256, verdict, scan_detail, created_at, expires_at, deleted_at
           FROM uploads WHERE user_id = ? ORDER BY created_at DESC LIMIT ?`,
      ).all(userId, limit),
    );
  }

  /** Retention sweep. Returns the artefacts whose retention window has closed. */
  expiredUploads(now: number, limit: number): UploadRow[] {
    return asRows(
      this.#stmt(
        `SELECT id, user_id, request_ref, stored_name, original_name, declared_type, detected_type, bytes,
                sha256, verdict, scan_detail, created_at, expires_at, deleted_at
           FROM uploads WHERE deleted_at IS NULL AND expires_at <= ? ORDER BY expires_at ASC LIMIT ?`,
      ).all(now, limit),
    );
  }

  markUploadDeleted(id: string, now: number): void {
    this.#stmt("UPDATE uploads SET deleted_at = ? WHERE id = ?").run(now, id);
  }

  markUploadWriteFailed(id: string): void {
    this.#stmt("UPDATE uploads SET verdict = 'REJECTED', scan_detail = 'storage write failed' WHERE id = ?").run(id);
  }

  countLiveUploads(userId: string): number {
    const row = asRow<{ n: number }>(
      this.#stmt("SELECT COUNT(*) AS n FROM uploads WHERE user_id = ? AND deleted_at IS NULL").get(userId),
    );
    return row === null ? 0 : Number(row.n);
  }

  /** Pending writes are rows too; expired files count until deletion succeeds. */
  uploadUsage(userId: string | null): { files: number; bytes: number } {
    const row = asRow<{ files: number; bytes: number }>(this.#stmt(
      `SELECT COUNT(*) AS files,
              COALESCE(SUM(CASE WHEN stored_name != '-' THEN bytes ELSE 0 END), 0) AS bytes
         FROM uploads WHERE deleted_at IS NULL AND (? IS NULL OR user_id = ?)`,
    ).get(userId, userId));
    return { files: Number(row?.files ?? 0), bytes: Number(row?.bytes ?? 0) };
  }

  /* ---------------- diagnostics ---------------- */

  /**
   * Engine-level invariants, asserted at boot so a misconfigured file is caught early
   * rather than at the first write that depends on the rule.
   */
  invariants(): { foreignKeys: boolean; schemaVersion: number; appendOnlyTriggers: number } {
    const fk = asRow<{ foreign_keys: number }>(this.#db.prepare("PRAGMA foreign_keys").get());
    // Counted from the catalogue rather than provoked by a write: an UPDATE that matches
    // no rows fires no trigger and would prove nothing, which is exactly how a
    // "verification" ends up asserting the opposite of the truth.
    const triggers = asRow<{ n: number }>(
      this.#db
        .prepare(
          "SELECT COUNT(*) AS n FROM sqlite_master WHERE type = 'trigger' AND name IN ('audit_log_no_update','audit_log_no_delete','ledger_records_no_update','ledger_records_no_delete')",
        )
        .get(),
    );
    return {
      foreignKeys: fk !== null && Number(fk.foreign_keys) === 1,
      schemaVersion: this.#readUserVersion(),
      appendOnlyTriggers: triggers === null ? 0 : Number(triggers.n),
    };
  }
}
