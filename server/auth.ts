/**
 * Authentication and session authority.
 *
 * THE SHAPE OF THE DECISION, because most of this file follows from it.
 *
 * Sessions are SERVER-SIDE records. The browser holds an opaque random string in an
 * `HttpOnly` cookie; every fact about the session — who it belongs to, its role, when it
 * dies, whether it is revoked — lives in the database. Nothing about authority is
 * encoded in the value the client holds, so there is nothing in it to forge, and nothing
 * is stored anywhere a script can read. That last part is what "no local auth tokens"
 * means concretely: there is no bearer token in `localStorage`, no JWT whose claims the
 * server must trust, and no client-side flag that says whether someone is an admin.
 *
 * The database stores only a digest of the session secret. A leaked backup of the
 * sessions table therefore grants no ability to present a session, because the value
 * needed to authenticate is not in the row — the same reasoning as password hashing,
 * applied to the other credential in the system.
 *
 * CSRF USES A SYNCHRONISER TOKEN, NOT A DOUBLE-SUBMIT COOKIE. The token is derived from
 * the session cookie with the server key, handed to the page by `GET /v1/auth/me`, and
 * must come back in a header on every mutation. A cross-site request can carry the
 * session cookie, but it cannot read this session's response, so it cannot obtain the
 * token. Combined with `SameSite=Strict` and the existing same-origin check, a
 * state-changing request has to satisfy three independent conditions.
 *
 * DERIVED, NOT STORED, AND THAT MATTERS FOR MORE THAN TIDINESS. A stored token can only
 * be handed out once, so issuing a usable token to a reloaded page means invalidating the
 * old one — and a system where two tabs invalidate each other's token is a system whose
 * CSRF defence fires on its own users. Deriving it makes it stable for the life of the
 * session while remaining unreadable to any other origin.
 *
 * EVERY FAILURE IS THE SAME FAILURE. Unknown address, wrong password, suspended account
 * and locked account all return one indistinguishable rejection, and the unknown-address
 * path burns the same scrypt work as the real one. The audit log records which it was,
 * because the operator needs to know and the caller must not.
 */
import { createHmac, randomBytes, timingSafeEqual } from "node:crypto";
import { SESSION_TTL_MS, SESSION_TOUCH_MS, Store, type Role, type UserRow } from "./db.ts";
import { checkPassword, hashPassword, unusableDigest, verifyAbsent, verifyPassword } from "./passwords.ts";

/** Cookie name. Not `__Host-`-prefixed: that prefix demands `Secure`, which local HTTP cannot set. */
export const SESSION_COOKIE = "zeus_session";

/** CSRF header. A header, not a form field, so it cannot be produced by a plain form post. */
export const CSRF_HEADER = "x-zeus-csrf";

/** Failed authentications before an account is briefly locked. */
const MAX_FAILURES = 8;
const LOCK_MS = 15 * 60 * 1_000;

/** The privacy policy version a signup consents to. Bumping it re-prompts every account. */
export const PRIVACY_VERSION = "2026-10-07";
export const TERMS_VERSION = "2026-10-07";

export type Identity = {
  readonly userId: string;
  readonly sessionId: string;
  readonly email: string;
  readonly displayName: string;
  readonly role: Role;
  readonly mustChangePassword: boolean;
  /** Raw synchroniser token, for the caller to reveal to the page that owns the session. */
  readonly csrf: string;
};

export type AuthOk<T> = { readonly ok: true; readonly value: T };
export type AuthErr = {
  readonly ok: false;
  /** Machine code for the audit record and for tests. Never rendered. */
  readonly code: string;
  /** The single, uninformative message every authentication failure returns. */
  readonly msg: string;
  readonly status: number;
};
export type AuthResult<T> = AuthOk<T> | AuthErr;

export type RequestContext = {
  /** Hash of the source address. The raw address is never stored or logged. */
  readonly ipHash: string;
  readonly ip: string;
  readonly userAgent: string;
};

export type AuthConfig = {
  readonly store: Store;
  /** HMAC key for session, CSRF and address digests. Rotating it invalidates every session. */
  readonly sessionKey: Buffer;
  readonly cookieSecure: boolean;
  readonly now: () => number;
};

/** The one message every failed authentication returns. */
const GENERIC_FAILURE = "those credentials are not valid";
const GENERIC_SIGNUP = "an account cannot be created with those details; if you already have one, sign in instead";

function id(): string {
  return randomBytes(16).toString("hex");
}

function token(): string {
  return randomBytes(32).toString("base64url");
}

/** Domain-separated digest so one key can serve several purposes without collisions. */
function digest(key: Buffer, domain: string, value: string): string {
  return createHmac("sha256", key).update(`${domain}\u0000${value}`, "utf8").digest("hex");
}

const EMAIL_SHAPE = /^[A-Za-z0-9._%+-]{1,64}@[A-Za-z0-9-]{1,63}(?:\.[A-Za-z0-9-]{1,63})+$/;

export function normalizeEmail(value: string): string {
  return value.trim().toLowerCase();
}

/* ------------------------------------------------------------------ */
/*  Cookies                                                            */
/* ------------------------------------------------------------------ */

export type CookieOptions = {
  readonly maxAgeSeconds: number;
  readonly secure: boolean;
};

/**
 * Serialise one cookie.
 *
 * `HttpOnly` keeps it away from scripts, so an injected script cannot exfiltrate a
 * session. `SameSite=Strict` means the browser will not attach it to a request
 * originating from another site at all, which removes the practical basis of CSRF
 * before the token check is even reached. `Path=/` with no `Domain` keeps it first-party.
 */
export function serialiseCookie(name: string, value: string, options: CookieOptions): string {
  const parts = [`${name}=${encodeURIComponent(value)}`, "Path=/", "HttpOnly", "SameSite=Strict"];
  if (options.maxAgeSeconds <= 0) parts.push("Max-Age=0");
  else parts.push(`Max-Age=${Math.floor(options.maxAgeSeconds)}`);
  if (options.secure) parts.push("Secure");
  return parts.join("; ");
}

/** Parse a `Cookie:` header. Malformed pairs are skipped rather than throwing. */
export function parseCookies(header: string | null): Map<string, string> {
  const out = new Map<string, string>();
  if (header === null) return out;
  for (const part of header.split(";")) {
    const eq = part.indexOf("=");
    if (eq <= 0) continue;
    const name = part.slice(0, eq).trim();
    const raw = part.slice(eq + 1).trim();
    if (name === "") continue;
    try {
      out.set(name, decodeURIComponent(raw));
    } catch {
      // A cookie with a broken escape is not a cookie.
    }
  }
  return out;
}

export function sessionCookie(value: string, secure: boolean): string {
  return serialiseCookie(SESSION_COOKIE, value, { maxAgeSeconds: SESSION_TTL_MS / 1_000, secure });
}

export function clearSessionCookie(secure: boolean): string {
  return serialiseCookie(SESSION_COOKIE, "", { maxAgeSeconds: 0, secure });
}

/** Address and user-agent are reduced to digests so the audit trail carries no raw network data. */
export function contextHash(sessionKey: Buffer, domain: "ip" | "ua", value: string): string {
  return digest(sessionKey, domain, value).slice(0, 32);
}

/* ------------------------------------------------------------------ */
/*  Service                                                            */
/* ------------------------------------------------------------------ */

export type SignupInput = {
  readonly email: string;
  readonly displayName: string;
  readonly password: string;
  /** Must be literally true. The privacy policy is accepted by the act of signup. */
  readonly acceptPrivacy: boolean;
  readonly acceptTerms: boolean;
  /** Optional marketing consent. Absent consent is the default and is recorded as such. */
  readonly acceptMarketing: boolean;
};

export type SessionGrant = {
  readonly identity: Identity;
  readonly cookie: string;
  /** Set-Cookie value that removes any pre-existing session, for rotation paths. */
  readonly clearCookie: string | null;
};

export class Auth {
  readonly #store: Store;
  readonly #sessionKey: Buffer;
  readonly #cookieSecure: boolean;
  readonly #now: () => number;

  constructor(config: AuthConfig) {
    this.#store = config.store;
    this.#sessionKey = config.sessionKey;
    this.#cookieSecure = config.cookieSecure;
    this.#now = config.now;
  }

  get cookieSecure(): boolean {
    return this.#cookieSecure;
  }

  /**
   * Reduce a source address to a stable digest.
   *
   * Exposed as a method rather than as the key itself. Callers that need to key a rate
   * limit or an audit row on an address get the ability to do exactly that, and not the
   * ability to read the material every session in the system is derived from.
   */
  ipDigest(source: string): string {
    return digest(this.#sessionKey, "ip", source).slice(0, 32);
  }

  /* ---------------- session mechanics ---------------- */

  #tokenHash(raw: string): string {
    return digest(this.#sessionKey, "session", raw);
  }

  #csrfHash(raw: string): string {
    return digest(this.#sessionKey, "csrf", raw);
  }

  /**
   * The synchroniser token for a session, derived rather than stored.
   *
   * This is the fix for a defect worth naming. The token used to be a random value whose
   * digest was stored, which meant the plaintext existed only in the response that issued
   * it — and therefore that the only way to give a reloaded page a usable token was to
   * issue a new one. Every read of `/me` rotated it, so two tabs invalidated each other's
   * token and a mutation racing a poll was refused. A defence that fails closed on the
   * user's own concurrent requests is a defence people work around.
   *
   * Deriving it from the session cookie and the server key fixes that without weakening
   * anything: the value is stable for the life of the session, it is not stored anywhere,
   * it cannot be computed without the key, and it cannot be read by another origin because
   * reading it requires this session's response. A change in authority re-issues the
   * session — and therefore the cookie — which changes this value with it.
   */
  #csrfFor(rawSessionToken: string): string {
    return digest(this.#sessionKey, "csrf", rawSessionToken);
  }

  /** The synchroniser token a session should present. Never stored; recomputed on demand. */
  csrfFor(rawSessionToken: string): string {
    return this.#csrfFor(rawSessionToken);
  }

  /**
   * Issue a session and return the raw secrets exactly once.
   *
   * The raw values exist only in this function's scope and in the response. They are not
   * returned by any read path, which is why `Identity.csrf` comes from here rather than
   * from a lookup: after this call there is no way to recover them from the database.
   */
  #grant(user: UserRow, ctx: RequestContext): SessionGrant {
    const now = this.#now();
    const rawToken = token();
    // Derived from the cookie, so the client's token is the same value this session will
    // expect on every mutation until the session itself is re-issued.
    const rawCsrf = this.#csrfFor(rawToken);
    // The id is generated here rather than inside the insert, because the identity
    // returned to the caller has to name the session it was just granted — the CSRF
    // check on the very next mutation looks the row up by that id.
    const sessionId = id();
    this.#store.insertSession({
      id: sessionId,
      userId: user.id,
      tokenHash: this.#tokenHash(rawToken),
      // A digest of the derived token, kept as tamper evidence: if this row is edited, every
      // mutation on the session fails closed rather than silently accepting the edit.
      csrfHash: this.#csrfHash(rawCsrf),
      now,
      expiresAt: now + SESSION_TTL_MS,
      ipHash: ctx.ipHash,
      uaHash: digest(this.#sessionKey, "ua", ctx.userAgent).slice(0, 32),
    });
    return {
      identity: {
        userId: user.id,
        sessionId,
        email: user.email,
        displayName: user.display_name,
        role: user.role,
        mustChangePassword: user.must_change_password === 1,
        csrf: rawCsrf,
      },
      cookie: sessionCookie(rawToken, this.#cookieSecure),
      clearCookie: null,
    };
  }

  /**
   * Resolve a session cookie into an identity, or null.
   *
   * The request context is deliberately not a parameter. Binding a session to an address
   * or a user agent breaks real users — a phone moving between networks, a browser that
   * updated overnight — and enforcing it here would trade a small amount of theoretical
   * protection for a support burden. The digests are recorded at issue time for the
   * operator to look at, not used to reject; the controls that actually stop session
   * theft are rotation on authority change, a bounded absolute lifetime, and revocation.
   */
  resolve(rawCookie: string | null): Identity | null {
    if (rawCookie === null || rawCookie.length < 16 || rawCookie.length > 256) return null;
    const session = this.#store.sessionByTokenHash(this.#tokenHash(rawCookie));
    if (session === null) return null;

    const now = this.#now();
    if (session.revoked_at !== null || session.expires_at <= now) return null;

    const user = this.#store.userById(session.user_id);
    if (user === null || user.status !== "ACTIVE") {
      // A session belonging to an account that is gone or suspended stops working the
      // moment that becomes true, rather than at its stated expiry.
      this.#store.revokeSession(session.id, now);
      return null;
    }
    if (now - session.last_seen_at > SESSION_TOUCH_MS) this.#store.touchSession(session.id, now);

    // The CSRF token cannot be recovered from the row, so it is re-derived for the
    // caller by issuing a fresh one only when a mutation needs it. Reads carry no token.
    return {
      userId: user.id,
      sessionId: session.id,
      email: user.email,
      displayName: user.display_name,
      role: user.role,
      mustChangePassword: user.must_change_password === 1,
      csrf: "",
    };
  }

  /**
   * Verify the synchroniser token for a mutation on this session.
   *
   * The comparison is constant-time and, more importantly, is a comparison of digests
   * computed here: the caller's value is never the thing being compared against the
   * stored value directly, so the length of the caller's input cannot shorten the loop.
   */
  verifyCsrf(identity: Identity, rawSessionToken: string | null, presented: string | null): boolean {
    if (presented === null || presented.length === 0 || presented.length > 256) return false;
    if (rawSessionToken === null) return false;
    const row = this.#store.sessionById(identity.sessionId);
    if (row === null || row.revoked_at !== null) return false;

    const expectedToken = this.#csrfFor(rawSessionToken);

    // Tamper evidence first: the row must still hold the digest of the token this session
    // derives. An edited row is refused, so a database write cannot widen this check.
    const stored = Buffer.from(row.csrf_hash, "hex");
    const derived = Buffer.from(this.#csrfHash(expectedToken), "hex");
    if (stored.length !== derived.length || !timingSafeEqual(stored, derived)) return false;

    // Then the caller's token, against the derived one. Both sides are fixed-length hex of
    // the same length, so nothing about the comparison depends on what was sent.
    const expected = Buffer.from(expectedToken, "utf8");
    const actual = Buffer.from(presented, "utf8");
    if (expected.length !== actual.length) return false;
    return timingSafeEqual(expected, actual);
  }

  logout(identity: Identity, ctx: RequestContext): void {
    const now = this.#now();
    this.#store.revokeSession(identity.sessionId, now);
    this.#store.audit({
      ts: now,
      actorId: identity.userId,
      actorRole: identity.role,
      action: "AUTH.LOGOUT",
      subjectId: identity.userId,
      outcome: "OK",
      detail: "session revoked",
      ipHash: ctx.ipHash,
    });
  }

  /* ---------------- signup ---------------- */

  async signup(input: SignupInput, ctx: RequestContext): Promise<AuthResult<SessionGrant>> {
    const now = this.#now();
    const email = normalizeEmail(input.email);
    const displayName = input.displayName.trim();

    // Consent is checked before anything is written. An account created without a
    // recorded policy acceptance is a compliance defect that cannot be repaired
    // afterwards, because the moment of signup cannot be reconstructed.
    if (input.acceptPrivacy !== true || input.acceptTerms !== true) {
      this.#store.audit({
        ts: now,
        actorId: null,
        actorRole: "ANON",
        action: "AUTH.SIGNUP",
        subjectId: null,
        outcome: "REFUSED",
        detail: "policy not accepted",
        ipHash: ctx.ipHash,
      });
      return { ok: false, code: "CONSENT_REQUIRED", msg: "the privacy policy and terms must be accepted", status: 400 };
    }
    if (!EMAIL_SHAPE.test(email) || email.length > 254) {
      return { ok: false, code: "BAD_EMAIL", msg: GENERIC_SIGNUP, status: 400 };
    }
    if (displayName.length < 1 || displayName.length > 80) {
      return { ok: false, code: "BAD_NAME", msg: "a display name of 1 to 80 characters is required", status: 400 };
    }
    const problem = checkPassword(input.password, email);
    if (problem !== null) return { ok: false, code: problem.code, msg: problem.msg, status: 400 };

    if (this.#store.userByEmail(email) !== null) {
      // Deliberately indistinguishable from a generic failure. Creating the account and
      // reporting success would be a lie; saying "already registered" is an oracle. The
      // audit record is where the truth goes.
      this.#store.audit({
        ts: now,
        actorId: null,
        actorRole: "ANON",
        action: "AUTH.SIGNUP",
        subjectId: null,
        outcome: "REFUSED",
        detail: "address already registered",
        ipHash: ctx.ipHash,
      });
      return { ok: false, code: "EMAIL_TAKEN", msg: GENERIC_SIGNUP, status: 409 };
    }

    const pwdHash = await hashPassword(input.password);
    const userId = id();
    try {
      this.#store.tx(() => {
        this.#store.insertUser({ id: userId, email, displayName, role: "CUSTOMER", pwdHash, now, mustChangePassword: false });
        this.#store.grantConsent({ id: id(), userId, kind: "PRIVACY", version: PRIVACY_VERSION, now });
        this.#store.grantConsent({ id: id(), userId, kind: "TERMS", version: TERMS_VERSION, now });
        if (input.acceptMarketing) {
          this.#store.grantConsent({ id: id(), userId, kind: "MARKETING", version: "1", now });
        }
      });
    } catch {
      // The unique index is the real guard against a race between two concurrent
      // signups for one address; this path is that race losing.
      this.#store.audit({
        ts: now,
        actorId: null,
        actorRole: "ANON",
        action: "AUTH.SIGNUP",
        subjectId: null,
        outcome: "REFUSED",
        detail: "address already registered",
        ipHash: ctx.ipHash,
      });
      return { ok: false, code: "EMAIL_TAKEN", msg: GENERIC_SIGNUP, status: 409 };
    }

    const user = this.#store.userById(userId);
    if (user === null) return { ok: false, code: "INTERNAL", msg: GENERIC_SIGNUP, status: 500 };

    this.#store.audit({
      ts: now,
      actorId: userId,
      actorRole: "CUSTOMER",
      action: "AUTH.SIGNUP",
      subjectId: userId,
      outcome: "OK",
      detail: `privacy=${PRIVACY_VERSION} terms=${TERMS_VERSION} marketing=${input.acceptMarketing ? "1" : "0"}`,
      ipHash: ctx.ipHash,
    });

    return { ok: true, value: this.#grant(user, ctx) };
  }

  /* ---------------- login ---------------- */

  async login(email: string, password: string, ctx: RequestContext): Promise<AuthResult<SessionGrant>> {
    const now = this.#now();
    const normalized = normalizeEmail(email);
    const user = this.#store.userByEmail(normalized);

    if (user === null) {
      // Same work as a real verification, so the response time does not answer the
      // question the response body refuses to.
      await verifyAbsent(password);
      this.#auditLogin(now, null, ctx, "REFUSED", "unknown address");
      return { ok: false, code: "BAD_CREDENTIALS", msg: GENERIC_FAILURE, status: 401 };
    }

    if (user.locked_until > now) {
      this.#auditLogin(now, user, ctx, "REFUSED", "account locked");
      return { ok: false, code: "BAD_CREDENTIALS", msg: GENERIC_FAILURE, status: 401 };
    }

    const match = await verifyPassword(password, user.pwd_hash);
    if (!match) {
      this.#store.recordAuthFailure(user.id, now, MAX_FAILURES, LOCK_MS);
      this.#auditLogin(now, user, ctx, "REFUSED", "wrong password");
      return { ok: false, code: "BAD_CREDENTIALS", msg: GENERIC_FAILURE, status: 401 };
    }

    if (user.status !== "ACTIVE") {
      this.#auditLogin(now, user, ctx, "REFUSED", `account ${user.status}`);
      return { ok: false, code: "BAD_CREDENTIALS", msg: GENERIC_FAILURE, status: 401 };
    }

    this.#store.recordAuthSuccess(user.id, now);
    this.#auditLogin(now, user, ctx, "OK", `role=${user.role}`);
    return { ok: true, value: this.#grant(user, ctx) };
  }

  /**
   * Record an authentication attempt.
   *
   * The role comes from the account the attempt named, not from a constant. It used to be
   * the literal string `CUSTOMER`, which meant an administrator's sign-in was written into
   * the append-only log as a customer's — and the audit log is the evidence a reader has to
   * work from, so a wrong actor is worse than a missing one. For a refused attempt the role
   * is the role of the account targeted, which is the interesting fact: an attempt on an
   * administrator account reads differently from one on a customer account, even though the
   * response to the caller is identical either way.
   */
  #auditLogin(ts: number, user: UserRow | null, ctx: RequestContext, outcome: "OK" | "REFUSED", detail: string): void {
    this.#store.audit({
      ts,
      actorId: user === null ? null : user.id,
      actorRole: user === null ? "ANON" : user.role,
      action: "AUTH.LOGIN",
      subjectId: user === null ? null : user.id,
      outcome,
      detail,
      ipHash: ctx.ipHash,
    });
  }

  /* ---------------- password change ---------------- */

  async changePassword(
    identity: Identity,
    currentPassword: string,
    nextPassword: string,
    ctx: RequestContext,
  ): Promise<AuthResult<SessionGrant>> {
    const now = this.#now();
    const user = this.#store.userById(identity.userId);
    if (user === null) return { ok: false, code: "BAD_CREDENTIALS", msg: GENERIC_FAILURE, status: 401 };

    const match = await verifyPassword(currentPassword, user.pwd_hash);
    if (!match) {
      this.#store.audit({
        ts: now,
        actorId: user.id,
        actorRole: user.role,
        action: "AUTH.PASSWORD_CHANGED",
        subjectId: user.id,
        outcome: "REFUSED",
        detail: "current password incorrect",
        ipHash: ctx.ipHash,
      });
      return { ok: false, code: "BAD_CREDENTIALS", msg: "the current password is not correct", status: 401 };
    }

    const problem = checkPassword(nextPassword, user.email);
    if (problem !== null) return { ok: false, code: problem.code, msg: problem.msg, status: 400 };

    const pwdHash = await hashPassword(nextPassword);
    this.#store.tx(() => {
      this.#store.setPassword(user.id, pwdHash, now, false);
      // Every other session dies. A password change that leaves an attacker's existing
      // session alive has not changed anything that matters.
      this.#store.revokeUserSessions(user.id, now);
    });

    this.#store.audit({
      ts: now,
      actorId: user.id,
      actorRole: user.role,
      action: "AUTH.PASSWORD_CHANGED",
      subjectId: user.id,
      outcome: "OK",
      detail: "all other sessions revoked",
      ipHash: ctx.ipHash,
    });

    const refreshed = this.#store.userById(user.id);
    if (refreshed === null) return { ok: false, code: "INTERNAL", msg: GENERIC_FAILURE, status: 500 };
    // The caller's own session was revoked above, so a new one is issued: the operator
    // stays signed in on the device they used, and nowhere else.
    const grant = this.#grant(refreshed, ctx);
    return { ok: true, value: { ...grant, clearCookie: clearSessionCookie(this.#cookieSecure) } };
  }

  /* ---------------- bootstrap ---------------- */

  /**
   * Create the first administrator if none exists.
   *
   * `must_change_password` is set, and every privileged route refuses to act while it is
   * set. A credential that arrived through an environment variable has been seen by
   * whoever configured the deployment and by whatever process listing read it, so it is
   * treated as a one-time secret rather than as a password.
   */
  async ensureBootstrapAdmin(env: NodeJS.ProcessEnv): Promise<string> {
    if (this.#store.countUsers("ADMIN") > 0) return "existing administrator present";
    const email = normalizeEmail(env["ZEUS_BOOTSTRAP_ADMIN_EMAIL"] ?? "");
    const password = env["ZEUS_BOOTSTRAP_ADMIN_PASSWORD"] ?? "";
    const now = this.#now();
    if (email === "" || password === "") {
      return "no administrator yet; set ZEUS_BOOTSTRAP_ADMIN_EMAIL and ZEUS_BOOTSTRAP_ADMIN_PASSWORD once";
    }
    if (!EMAIL_SHAPE.test(email) || checkPassword(password, email) !== null) {
      return "bootstrap administrator rejected: address or password does not meet policy";
    }
    const pwdHash = await hashPassword(password);
    const userId = id();
    this.#store.insertUser({
      id: userId,
      email,
      displayName: "Bootstrap Administrator",
      role: "ADMIN",
      pwdHash,
      now,
      mustChangePassword: true,
    });
    this.#store.audit({
      ts: now,
      actorId: null,
      actorRole: "SYSTEM",
      action: "ADMIN.BOOTSTRAP",
      subjectId: userId,
      outcome: "OK",
      detail: "paid nothing: created from environment, password change required",
      ipHash: "",
    });
    return "bootstrap administrator created; change the password on first sign-in";
  }

  /**
   * Drop sessions that can no longer authenticate anyone: expired, or already revoked.
   *
   * Revoked rows are removed rather than kept as history, because the audit log already
   * holds the durable record of the revocation and a table that only grows is a table
   * that eventually becomes a liability. Bounded housekeeping, called from the sweep.
   */
  prune(): number {
    return this.#store.pruneSessions(this.#now());
  }

  /** Disable an account and end its sessions. The audit record is written by the route. */
  resetToUnusable(userId: string): Promise<string> {
    return unusableDigest().then((hash) => {
      const now = this.#now();
      this.#store.tx(() => {
        this.#store.setPassword(userId, hash, now, true);
        this.#store.revokeUserSessions(userId, now);
      });
      return "credentials replaced with an unusable digest";
    });
  }
}
