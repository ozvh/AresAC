/**
 * Account, subscription, upload and administration routes.
 *
 * THE ONE RULE THIS FILE EXISTS TO HOLD: authority is decided here, on the server, from a
 * session record, on every request. Nothing a page sends is evidence of anything. A
 * request body may name a subscription; it cannot name an owner. A response may describe a
 * role; no request may claim one. The admin surface is not hidden behind a client-side
 * condition anywhere — every admin route re-derives the caller's role from the database
 * and refuses before it reads a single row of anybody else's data.
 *
 * FOUR GUARDS, APPLIED IN THIS ORDER, EVERY TIME:
 *
 *   1. SAME ORIGIN. A browser naming an unconfigured origin is refused outright.
 *   2. SESSION. A record in the database, not a token the client holds.
 *   3. CSRF. A synchroniser token that only the page holding the session can read.
 *   4. ROLE. Checked against the row, and a bootstrap account that still carries
 *      `must_change_password` is refused every privileged action until it changes it.
 *
 * Dispatch is keyed by `METHOD path`, so a route cannot be reached by the wrong verb: a
 * GET on a mutating path has no handler to find rather than a handler it must remember to
 * refuse. That is the difference between a rule and a habit.
 */
import type { IncomingMessage, ServerResponse } from "node:http";
import { SESSION_COOKIE, parseCookies, serialiseCookie, type Identity } from "./auth.ts";
import type { Role } from "./db.ts";
import { addCookie, fail, header, json, jsonContentType, originAllowed, readBody, sourceOf } from "./http-kit.ts";
import type { Runtime } from "./runtime.ts";
import { PLANS, parseCancel } from "./subscriptions.ts";
import { UPLOAD_MAX_BASE64 } from "./uploads.ts";
import { PasswordWorkBusy } from "./passwords.ts";

export type AccountRouteConfig = {
  readonly runtime: Runtime;
  readonly consoleOrigins: readonly string[];
};

export type AccountRequest = {
  readonly req: IncomingMessage;
  readonly res: ServerResponse;
  readonly pathname: string;
  readonly method: string;
  readonly config: AccountRouteConfig;
};

/** Signup and login ceilings per source. Far below the ingest budget, for a different reason. */
/**
 * The global signup gate, adjustable with `ARES_SIGNUP_PER_MIN`.
 *
 * Every other limit in this system is charged against one account or one source, so the
 * only client that can trip it is the one it was written for. This one is charged against
 * the whole process, which makes it the only limit a legitimate launch can trip and the
 * only one an operator may need to raise. The default is unchanged, the value is bounded
 * so a typo cannot remove the gate, and the per-source gate above it is not adjustable —
 * that is the control that stops one caller from enumerating accounts.
 */
function signupCeiling(): { readonly perMin: number; readonly burst: number } {
  const raw = Number((process.env["ARES_SIGNUP_PER_MIN"] ?? "").trim());
  if (!Number.isFinite(raw) || raw < 1) return { perMin: SIGNUP_PER_MIN, burst: SIGNUP_BURST };
  const perMin = Math.min(100_000, Math.floor(raw));
  return { perMin, burst: Math.max(SIGNUP_BURST, Math.ceil(perMin / 2)) };
}

const AUTH_PER_MIN = 12;
const AUTH_BURST = 6;
/** Account creation is additionally capped process-wide, so a spray cannot mint accounts. */
const SIGNUP_PER_MIN = 6;
const SIGNUP_BURST = 3;

const BODY_SMALL = 2_048;
const BODY_TINY = 512;
const BODY_UPLOAD = UPLOAD_MAX_BASE64 + 1_024;

/* ------------------------------------------------------------------ */
/*  Guards                                                             */
/* ------------------------------------------------------------------ */

function rate(runtime: Runtime, key: string, now: number, perMin: number, burst: number): boolean {
  return runtime.limiter.take(key, now, perMin / 60, burst);
}

/**
 * Guard 1, plus the JSON discipline every write path in the system requires.
 *
 * `text/plain` and form encodings are refused, so the classic cross-site request shapes
 * are not even parseable here. `SameSite=Strict` and the synchroniser token are the other
 * two layers; neither of them makes this one redundant.
 */
function preflight(request: AccountRequest): boolean {
  const { req, res, config } = request;
  if (!originAllowed(req, config.consoleOrigins)) {
    fail(res, 403, "FORBIDDEN", "origin refused");
    return false;
  }
  if (request.method === "POST" && !jsonContentType(req)) {
    fail(res, 415, "BAD_CT", "application/json required");
    return false;
  }
  return true;
}

/**
 * Guards 2, 3 and 4.
 *
 * `role` is the minimum authority the route requires; null means any signed-in account.
 * CSRF is demanded on every mutation and never on a read, because requiring it on reads
 * would push the token into more places than it needs to exist in.
 */
function authorise(
  request: AccountRequest,
  options: { readonly role: Role | null; readonly mutation: boolean },
): { readonly identity: Identity; readonly ipHash: string } | null {
  const { req, res, config } = request;
  const { runtime } = config;
  const ipHash = runtime.auth.ipDigest(sourceOf(req));

  const rawCookie = parseCookies(header(req, "cookie")).get(SESSION_COOKIE) ?? null;
  const identity = runtime.auth.resolve(rawCookie);
  if (identity === null) {
    // No session and an expired session are the same answer on purpose: telling a caller
    // which of the two it was helps only a caller who should not have one.
    fail(res, 401, "SIG", "a signed-in session is required");
    return null;
  }

  // The token is derived from the cookie, so the guard needs both: the session names the
  // expected value, and the cookie is what it is derived from.
  if (options.mutation && !runtime.auth.verifyCsrf(identity, rawCookie, header(req, "x-ares-csrf"))) {
    fail(res, 403, "FORBIDDEN", "the request did not carry this session's token");
    return null;
  }

  if (options.role !== null) {
    if (identity.role !== options.role) {
      // Audited as a refusal: an authenticated account reaching for authority it does not
      // hold is the most interesting event this system can record.
      runtime.store.audit({
        ts: Date.now(),
        actorId: identity.userId,
        actorRole: identity.role,
        action: "AUTHZ.REFUSED",
        subjectId: identity.userId,
        outcome: "REFUSED",
        detail: `required ${options.role}, held ${identity.role} at ${request.pathname}`,
        ipHash,
      });
      fail(res, 403, "FORBIDDEN", "this account does not have that authority");
      return null;
    }
    if (identity.mustChangePassword) {
      // A credential delivered out of band has been seen by whoever configured the
      // deployment. It buys a password change and nothing else.
      fail(res, 403, "FORBIDDEN", "the password on this account must be changed first");
      return null;
    }
  }

  return { identity, ipHash };
}

function setSession(res: ServerResponse, cookie: string): void {
  addCookie(res, cookie);
}

function clearSession(res: ServerResponse, secure: boolean): void {
  addCookie(res, serialiseCookie(SESSION_COOKIE, "", { maxAgeSeconds: 0, secure }));
}

/** Map an authentication result's status onto the shared error vocabulary. */
function authCode(status: number): "SCHEMA" | "REPLAY" | "RATE" | "SIG" | "MALFORMED" {
  if (status === 409) return "REPLAY";
  if (status === 429) return "RATE";
  if (status === 401) return "SIG";
  if (status === 500) return "MALFORMED";
  return "SCHEMA";
}

function publicUser(identity: Identity): Record<string, unknown> {
  return {
    email: identity.email,
    displayName: identity.displayName,
    role: identity.role,
    mustChangePassword: identity.mustChangePassword,
  };
}

/* ------------------------------------------------------------------ */
/*  Handlers                                                           */
/* ------------------------------------------------------------------ */

async function signup(request: AccountRequest): Promise<boolean> {
  const { req, res, config } = request;
  const { runtime } = config;
  const source = sourceOf(req);
  const now = Date.now();

  const ceiling = signupCeiling();
  if (
    !rate(runtime, `auth:${source}`, now, AUTH_PER_MIN, AUTH_BURST) ||
    !rate(runtime, "auth:__signup__", now, ceiling.perMin, ceiling.burst)
  ) {
    fail(res, 429, "RATE", "too many attempts from this source");
    return true;
  }

  const read = await readBody(req, BODY_SMALL);
  if (!read.ok) {
    if (read.reason === "ABORTED") fail(res, 400, "MALFORMED", "request aborted");
    else {
      res.on("finish", () => req.destroy());
      fail(res, 413, "TOO_LARGE", "body ceiling breached");
    }
    return true;
  }

  const parsed = parseSignup(read.body);
  if (!parsed.ok) {
    fail(res, 400, "SCHEMA", parsed.msg);
    return true;
  }

  const result = await runtime.auth.signup(parsed.input, {
    ipHash: runtime.auth.ipDigest(source),
    ip: source,
    userAgent: header(req, "user-agent") ?? "",
  });
  if (!result.ok) {
    fail(res, result.status, authCode(result.status), result.msg);
    return true;
  }

  setSession(res, result.value.cookie);
  json(res, 201, { ok: true, csrf: result.value.identity.csrf, user: publicUser(result.value.identity) });
  return true;
}

async function login(request: AccountRequest): Promise<boolean> {
  const { req, res, config } = request;
  const { runtime } = config;
  const source = sourceOf(req);

  if (!rate(runtime, `auth:${source}`, Date.now(), AUTH_PER_MIN, AUTH_BURST)) {
    fail(res, 429, "RATE", "too many attempts from this source");
    return true;
  }

  const read = await readBody(req, BODY_SMALL);
  if (!read.ok) {
    if (read.reason === "ABORTED") fail(res, 400, "MALFORMED", "request aborted");
    else {
      res.on("finish", () => req.destroy());
      fail(res, 413, "TOO_LARGE", "body ceiling breached");
    }
    return true;
  }

  const parsed = parseLogin(read.body);
  if (!parsed.ok) {
    fail(res, 400, "SCHEMA", parsed.msg);
    return true;
  }

  const result = await runtime.auth.login(parsed.input.email, parsed.input.password, {
    ipHash: runtime.auth.ipDigest(source),
    ip: source,
    userAgent: header(req, "user-agent") ?? "",
  });
  if (!result.ok) {
    // One status and one message for every failure: unknown address, wrong password,
    // suspended account or locked account. The audit log carries the distinction.
    fail(res, 401, "SIG", result.msg);
    return true;
  }

  setSession(res, result.value.cookie);
  json(res, 200, { ok: true, csrf: result.value.identity.csrf, user: publicUser(result.value.identity) });
  return true;
}

function logout(request: AccountRequest): boolean {
  const authorised = authorise(request, { role: null, mutation: true });
  if (authorised === null) return true;
  const { runtime } = request.config;
  runtime.auth.logout(authorised.identity, {
    ipHash: authorised.ipHash,
    ip: sourceOf(request.req),
    userAgent: header(request.req, "user-agent") ?? "",
  });
  clearSession(request.res, runtime.auth.cookieSecure);
  json(request.res, 200, { ok: true });
  return true;
}

function me(request: AccountRequest): boolean {
  const authorised = authorise(request, { role: null, mutation: false });
  if (authorised === null) return true;
  const { identity } = authorised;
  const { runtime } = request.config;
  const { store } = runtime;

  // The token is derived from the cookie rather than stored, so handing it out on a read
  // costs nothing and invalidates nothing: the same session gets the same value every
  // time, which is what lets two tabs of the account page coexist.
  const rawCookie = parseCookies(header(request.req, "cookie")).get(SESSION_COOKIE) ?? null;
  const csrf = rawCookie === null ? "" : runtime.auth.csrfFor(rawCookie);
  const subscription = store.activeSubscription(identity.userId);

  json(request.res, 200, {
    ok: true,
    csrf,
    user: publicUser(identity),
    consents: store.listConsents(identity.userId).map((row) => ({
      kind: row.kind,
      version: row.version,
      grantedAt: row.granted_at,
      withdrawn: row.withdrawn_at !== null,
    })),
    subscription:
      subscription === null
        ? null
        : {
            id: subscription.id,
            plan: subscription.plan,
            status: subscription.status,
            currentPeriodEnd: subscription.current_period_end,
            autoRenew: subscription.auto_renew === 1,
            cancelledAt: subscription.cancelled_at,
            cancelEffectiveAt: subscription.cancel_effective_at,
            noticeDays: runtime.subs.noticeDays,
            amountCents: PLANS[subscription.plan].amountCents,
          },
    uploads: store.uploadsForUser(identity.userId, 25).map((row) => ({
      id: row.id,
      originalName: row.original_name,
      bytes: row.bytes,
      verdict: row.verdict,
      createdAt: row.created_at,
      expiresAt: row.expires_at,
      deleted: row.deleted_at !== null,
    })),
    retentionDays: runtime.uploads.retentionDays,
  });
  return true;
}

async function changePassword(request: AccountRequest): Promise<boolean> {
  const authorised = authorise(request, { role: null, mutation: true });
  if (authorised === null) return true;
  const { runtime } = request.config;
  const now = Date.now();
  if (!rate(runtime, `password:user:${authorised.identity.userId}`, now, 6, 3) ||
      !rate(runtime, `password:source:${sourceOf(request.req)}`, now, AUTH_PER_MIN, AUTH_BURST)) {
    fail(request.res, 429, "RATE", "too many password-change attempts");
    return true;
  }

  const read = await readBody(request.req, BODY_SMALL);
  if (!read.ok) {
    fail(request.res, read.reason === "ABORTED" ? 400 : 413, read.reason === "ABORTED" ? "MALFORMED" : "TOO_LARGE", "body refused");
    return true;
  }
  const parsed = parsePassword(read.body);
  if (!parsed.ok) {
    fail(request.res, 400, "SCHEMA", parsed.msg);
    return true;
  }

  const result = await runtime.auth.changePassword(authorised.identity, parsed.input.current, parsed.input.next, {
    ipHash: authorised.ipHash,
    ip: sourceOf(request.req),
    userAgent: header(request.req, "user-agent") ?? "",
  });
  if (!result.ok) {
    fail(request.res, result.status, authCode(result.status), result.msg);
    return true;
  }
  setSession(request.res, result.value.cookie);
  json(request.res, 200, { ok: true, csrf: result.value.identity.csrf, user: publicUser(result.value.identity) });
  return true;
}

async function subscriptionMutation(request: AccountRequest): Promise<boolean> {
  const authorised = authorise(request, { role: null, mutation: true });
  if (authorised === null) return true;
  const { runtime } = request.config;

  const read = await readBody(request.req, BODY_TINY);
  if (!read.ok) {
    fail(request.res, read.reason === "ABORTED" ? 400 : 413, read.reason === "ABORTED" ? "MALFORMED" : "TOO_LARGE", "body refused");
    return true;
  }

  const cancelling = request.pathname === "/v1/subscription/cancel";
  const now = Date.now();
  if (cancelling) {
    const parsed = parseCancel(read.body);
    if (!parsed.ok) {
      fail(request.res, 400, "SCHEMA", parsed.msg);
      return true;
    }
    const result = runtime.subs.cancel(authorised.identity.userId, parsed.input, authorised.ipHash);
    if (!result.ok) {
      fail(request.res, result.status, result.status === 404 ? "NOT_FOUND" : "SCHEMA", result.msg);
      return true;
    }
    json(request.res, 200, {
      ok: true,
      subscription: {
        id: result.value.id,
        status: result.value.status,
        autoRenew: result.value.auto_renew === 1,
        currentPeriodEnd: result.value.current_period_end,
        cancelEffectiveAt: result.value.cancel_effective_at,
      },
    });
    return true;
  }

  const parsed = parseAutoRenew(read.body);
  if (!parsed.ok) {
    fail(request.res, 400, "SCHEMA", parsed.msg);
    return true;
  }
  const result = runtime.subs.setAutoRenew(
    authorised.identity.userId,
    parsed.input.subId,
    parsed.input.on,
    authorised.ipHash,
  );
  if (!result.ok) {
    fail(request.res, result.status, result.status === 404 ? "NOT_FOUND" : "SCHEMA", result.msg);
    return true;
  }
  void now;
  json(request.res, 200, {
    ok: true,
    subscription: {
      id: result.value.id,
      status: result.value.status,
      autoRenew: result.value.auto_renew === 1,
      currentPeriodEnd: result.value.current_period_end,
      cancelEffectiveAt: result.value.cancel_effective_at,
    },
  });
  return true;
}

async function intakeUpload(request: AccountRequest): Promise<boolean> {
  const authorised = authorise(request, { role: null, mutation: true });
  if (authorised === null) return true;
  const { runtime } = request.config;

  const declared = Number(header(request.req, "content-length") ?? "0");
  if (Number.isFinite(declared) && declared > BODY_UPLOAD) {
    fail(request.res, 413, "TOO_LARGE", "declared body exceeds ceiling");
    return true;
  }
  const read = await readBody(request.req, BODY_UPLOAD);
  if (!read.ok) {
    if (read.reason === "ABORTED") fail(request.res, 400, "MALFORMED", "request aborted");
    else {
      request.res.on("finish", () => request.req.destroy());
      fail(request.res, 413, "TOO_LARGE", "body ceiling breached");
    }
    return true;
  }
  if (!rate(runtime, `upload:${authorised.identity.userId}`, Date.now(), 10, 5)) {
    fail(request.res, 429, "RATE", "too many uploads");
    return true;
  }

  const result = await runtime.uploads.intake(read.body, authorised.identity.userId, authorised.ipHash);
  if (!result.ok) {
    fail(request.res, result.code === "TOO_LARGE" ? 413 : result.code === "STORAGE" ? 500 : 400, "SCHEMA", result.msg);
    return true;
  }
  // 202 for a quarantined artefact: the request was accepted and the record exists, but
  // nothing was stored. A client that treats any 2xx as "my file is on the server" is
  // wrong, and the verdict field is what tells it so.
  json(request.res, result.verdict === "QUARANTINED" ? 202 : 201, {
    ok: true,
    upload: {
      id: result.id,
      verdict: result.verdict,
      bytes: result.bytes,
      sha256: result.sha256,
      expiresAt: result.expiresAt,
      scanDetail: result.scanDetail,
      originalName: result.originalName,
    },
  });
  return true;
}

function listUploads(request: AccountRequest): boolean {
  const authorised = authorise(request, { role: null, mutation: false });
  if (authorised === null) return true;
  const { runtime } = request.config;
  // Scoped inside the accessor: there is no argument here that could ask for another
  // account's rows.
  const rows = runtime.store.uploadsForUser(authorised.identity.userId, 50);
  json(request.res, 200, {
    ok: true,
    retentionDays: runtime.uploads.retentionDays,
    uploads: rows.map((row) => ({
      id: row.id,
      originalName: row.original_name,
      declaredType: row.declared_type,
      detectedType: row.detected_type,
      bytes: row.bytes,
      verdict: row.verdict,
      scanDetail: row.scan_detail,
      createdAt: row.created_at,
      expiresAt: row.expires_at,
      deleted: row.deleted_at !== null,
    })),
  });
  return true;
}

function adminRead(request: AccountRequest): boolean {
  const authorised = authorise(request, { role: "ADMIN", mutation: false });
  if (authorised === null) return true;
  const { runtime } = request.config;
  const { store } = runtime;

  if (request.pathname === "/v1/admin/summary") {
    json(request.res, 200, {
      ok: true,
      accounts: { customers: store.countUsers("CUSTOMER"), admins: store.countUsers("ADMIN") },
      audit: { records: store.countAudit() },
      sessions: { live: store.countLiveSessions(authorised.identity.userId, Date.now()) },
      buildRequests: runtime.requests.stats(),
      retention: { uploadDays: runtime.uploads.retentionDays },
      renewal: { noticeDays: runtime.subs.noticeDays, plans: Object.keys(PLANS) },
    });
    return true;
  }

  if (request.pathname === "/v1/admin/users") {
    json(request.res, 200, {
      ok: true,
      users: store.listUsers(200, 0).map((row) => ({
        id: row.id,
        email: row.email,
        displayName: row.display_name,
        role: row.role,
        status: row.status,
        createdAt: row.created_at,
        lastLoginAt: row.last_login_at,
      })),
    });
    return true;
  }

  json(request.res, 200, {
    ok: true,
    audit: store.auditTail(200).map((row) => ({
      seq: row.seq,
      ts: row.ts,
      actorRole: row.actor_role,
      actorId: row.actor_id,
      action: row.action,
      subjectId: row.subject_id,
      outcome: row.outcome,
      detail: row.detail,
    })),
  });
  return true;
}

async function adminMutation(request: AccountRequest): Promise<boolean> {
  const authorised = authorise(request, { role: "ADMIN", mutation: true });
  if (authorised === null) return true;
  const { runtime } = request.config;

  const read = await readBody(request.req, BODY_TINY);
  if (!read.ok) {
    fail(request.res, read.reason === "ABORTED" ? 400 : 413, read.reason === "ABORTED" ? "MALFORMED" : "TOO_LARGE", "body refused");
    return true;
  }
  const parsed = parseAdminAction(read.body);
  if (!parsed.ok) {
    fail(request.res, 400, "SCHEMA", parsed.msg);
    return true;
  }

  const { store } = runtime;
  const now = Date.now();
  const target = store.userById(parsed.input.userId);
  if (target === null) {
    fail(request.res, 404, "NOT_FOUND", "no such account");
    return true;
  }

  // LOCKOUT PREVENTION. An administrator who can demote or suspend themselves can remove
  // the last account capable of administering the system, and once that has happened there
  // is no way back in through the interface.
  if (target.id === authorised.identity.userId) {
    fail(request.res, 403, "FORBIDDEN", "an administrator cannot change their own authority");
    return true;
  }
  const removingAdmin =
    target.role === "ADMIN" && (parsed.input.role === "CUSTOMER" || parsed.input.status === "SUSPENDED");
  if (removingAdmin && store.countUsers("ADMIN") <= 1) {
    fail(request.res, 409, "SCHEMA", "the last administrator cannot be demoted or suspended");
    return true;
  }

  store.tx(() => {
    if (parsed.input.role !== null) store.setUserRole(target.id, parsed.input.role, now);
    if (parsed.input.status !== null) {
      store.setUserStatus(target.id, parsed.input.status, now);
      // A suspended account would otherwise keep working until its session expired. The
      // sessions end at the same moment the status changes.
      if (parsed.input.status !== "ACTIVE") store.revokeUserSessions(target.id, now);
    }
  });

  store.audit({
    ts: now,
    actorId: authorised.identity.userId,
    actorRole: "ADMIN",
    action: "ADMIN.ACCOUNT_UPDATED",
    subjectId: target.id,
    outcome: "OK",
    detail: `role=${parsed.input.role ?? "unchanged"} status=${parsed.input.status ?? "unchanged"}`,
    ipHash: authorised.ipHash,
  });
  json(request.res, 200, { ok: true });
  return true;
}

/* ------------------------------------------------------------------ */
/*  Payload parsing. Closed key sets, bounded primitives, no coercion.  */
/* ------------------------------------------------------------------ */

type Parse<T> = { readonly ok: true; readonly input: T } | { readonly ok: false; readonly msg: string };

type Recorded =
  | { readonly ok: true; readonly record: Record<string, unknown> }
  | { readonly ok: false; readonly msg: string };

function obj(raw: string, keys: readonly string[]): Recorded {
  let parsed: unknown;
  try {
    parsed = JSON.parse(raw);
  } catch {
    return { ok: false, msg: "body is not JSON" };
  }
  if (typeof parsed !== "object" || parsed === null || Array.isArray(parsed)) {
    return { ok: false, msg: "body must be an object" };
  }
  const record = parsed as Record<string, unknown>;
  if (Object.keys(record).length !== keys.length) return { ok: false, msg: "unknown or missing fields" };
  for (const key of keys) {
    if (!Object.hasOwn(record, key)) return { ok: false, msg: `missing field ${key}` };
  }
  return { ok: true, record };
}

export type SignupPayload = {
  readonly email: string;
  readonly displayName: string;
  readonly password: string;
  readonly acceptPrivacy: boolean;
  readonly acceptTerms: boolean;
  readonly acceptMarketing: boolean;
};

export function parseSignup(raw: string): Parse<SignupPayload> {
  const shape = obj(raw, ["email", "displayName", "password", "acceptPrivacy", "acceptTerms", "acceptMarketing"]);
  if (!shape.ok) return shape;
  const { email, displayName, password, acceptPrivacy, acceptTerms, acceptMarketing } = shape.record;
  if (typeof email !== "string" || email.length > 254) return { ok: false, msg: "email must be a string" };
  if (typeof displayName !== "string" || displayName.length > 80) return { ok: false, msg: "displayName must be a string" };
  if (typeof password !== "string" || password.length > 200) return { ok: false, msg: "password must be a string" };
  if (typeof acceptPrivacy !== "boolean" || typeof acceptTerms !== "boolean") {
    return { ok: false, msg: "policy consent must be a boolean" };
  }
  if (typeof acceptMarketing !== "boolean") return { ok: false, msg: "marketing consent must be a boolean" };
  return { ok: true, input: { email, displayName, password, acceptPrivacy, acceptTerms, acceptMarketing } };
}

export function parseLogin(raw: string): Parse<{ readonly email: string; readonly password: string }> {
  const shape = obj(raw, ["email", "password"]);
  if (!shape.ok) return shape;
  const { email, password } = shape.record;
  if (typeof email !== "string" || email.length === 0 || email.length > 254) {
    return { ok: false, msg: "email must be a string" };
  }
  if (typeof password !== "string" || password.length === 0 || password.length > 200) {
    return { ok: false, msg: "password must be a string" };
  }
  return { ok: true, input: { email, password } };
}

export function parsePassword(raw: string): Parse<{ readonly current: string; readonly next: string }> {
  const shape = obj(raw, ["current", "next"]);
  if (!shape.ok) return shape;
  const { current, next } = shape.record;
  if (typeof current !== "string" || current.length > 200) return { ok: false, msg: "current must be a string" };
  if (typeof next !== "string" || next.length > 200) return { ok: false, msg: "next must be a string" };
  return { ok: true, input: { current, next } };
}

export function parseAutoRenew(raw: string): Parse<{ readonly subId: string; readonly on: boolean }> {
  const shape = obj(raw, ["subId", "on"]);
  if (!shape.ok) return shape;
  const { subId, on } = shape.record;
  if (typeof subId !== "string" || !/^[0-9a-f]{32}$/.test(subId)) return { ok: false, msg: "subId is not an identifier" };
  if (typeof on !== "boolean") return { ok: false, msg: "on must be a boolean" };
  return { ok: true, input: { subId, on } };
}

export type AdminAction = {
  readonly userId: string;
  readonly role: Role | null;
  readonly status: "ACTIVE" | "SUSPENDED" | "CLOSED" | null;
};

export function parseAdminAction(raw: string): Parse<AdminAction> {
  const shape = obj(raw, ["userId", "role", "status"]);
  if (!shape.ok) return shape;
  const { userId, role, status } = shape.record;
  if (typeof userId !== "string" || !/^[0-9a-f]{32}$/.test(userId)) return { ok: false, msg: "userId is not an identifier" };

  let nextRole: Role | null = null;
  if (role !== null) {
    if (role !== "CUSTOMER" && role !== "ADMIN") return { ok: false, msg: "role is not a known role" };
    nextRole = role;
  }
  let nextStatus: AdminAction["status"] = null;
  if (status !== null) {
    if (status !== "ACTIVE" && status !== "SUSPENDED" && status !== "CLOSED") {
      return { ok: false, msg: "status is not a known status" };
    }
    nextStatus = status;
  }
  if (nextRole === null && nextStatus === null) return { ok: false, msg: "nothing to change" };
  return { ok: true, input: { userId, role: nextRole, status: nextStatus } };
}

/* ------------------------------------------------------------------ */
/*  Dispatch                                                           */
/* ------------------------------------------------------------------ */

const ROUTES: Readonly<Record<string, (request: AccountRequest) => Promise<boolean> | boolean>> = {
  "POST /v1/auth/signup": signup,
  "POST /v1/auth/login": login,
  "POST /v1/auth/logout": logout,
  "POST /v1/auth/password": changePassword,
  "GET /v1/auth/me": me,
  "POST /v1/subscription/cancel": subscriptionMutation,
  "POST /v1/subscription/autorenew": subscriptionMutation,
  "GET /v1/uploads": listUploads,
  "POST /v1/uploads": intakeUpload,
  "GET /v1/admin/summary": adminRead,
  "GET /v1/admin/users": adminRead,
  "GET /v1/admin/audit": adminRead,
  "POST /v1/admin/user": adminMutation,
};

/** Paths this module owns, so a wrong verb is a 405 rather than the console shell. */
const OWNED = new Set<string>(Object.keys(ROUTES).map((key) => key.slice(key.indexOf(" ") + 1)));

export function ownsAccountPath(pathname: string): boolean {
  return OWNED.has(pathname);
}

/**
 * True when this module handled the request. False hands it back to the caller.
 *
 * A path this module owns with a verb it does not accept answers 405 here, including
 * before the origin check, so probing the admin surface with a GET cannot distinguish an
 * existing route from a missing one by its status code alone.
 */
export async function handleAccountRoutes(request: AccountRequest): Promise<boolean> {
  const handler = ROUTES[`${request.method} ${request.pathname}`];
  if (handler === undefined) {
    if (!OWNED.has(request.pathname)) return false;
    const methods = Object.keys(ROUTES)
      .filter((key) => key.endsWith(` ${request.pathname}`))
      .map((key) => key.slice(0, key.indexOf(" ")));
    fail(request.res, 405, "BAD_METHOD", `${methods.join("/")} required`);
    return true;
  }
  if (!preflight(request)) return true;
  try {
    return await handler(request);
  } catch (error) {
    if (!(error instanceof PasswordWorkBusy)) throw error;
    fail(request.res, 503, "RATE", "password service is busy; retry later");
    return true;
  }
}
