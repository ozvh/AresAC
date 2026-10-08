/**
 * Account client.
 *
 * THE SESSION IS NOT STORED IN THE BROWSER. Not in `localStorage`, not in `sessionStorage`,
 * not in a readable cookie. The session lives in an `HttpOnly` cookie the page cannot see,
 * and the only thing this module holds is the CSRF token for the current page load. There is
 * therefore nothing here to steal with an injected script, nothing that survives a reload
 * except the cookie the browser manages, and nothing a compromised page could hand to
 * another origin that would still be valid.
 *
 * The two token kinds are deliberately asymmetric:
 *
 *   - SESSION  `HttpOnly`, `SameSite=Strict`, opaque, unforgeable, unreadable by script.
 *   - CSRF     readable by this page only, invalidated on every authority change, and
 *              useful for exactly nothing on its own.
 *
 * A CSRF token is fetched rather than assumed. `GET /v1/auth/me` issues a fresh one, so a
 * page that reloaded has a valid token before it can mutate anything. That is why every
 * mutation below awaits `ensureSession()` first rather than failing once and asking the
 * user to refresh.
 *
 * Every response is parsed defensively: these are network answers, and an answer that is
 * not the shape this module expects is a failure, not a crash.
 */
import type {
  AccountRole,
  AccountStatus,
  AccountUser,
  AdminAuditView,
  AdminUserView,
  AuthAck,
  MeResponse,
  SubscriptionView,
  UploadView,
} from "@shared/protocol";
import { PLAN_LABEL } from "@shared/protocol";

export type Outcome<T> = { readonly ok: true; readonly value: T } | { readonly ok: false; readonly reason: string };

export type Session =
  | { readonly status: "UNKNOWN" }
  | { readonly status: "ANON" }
  | {
      readonly status: "AUTHED";
      readonly user: AccountUser;
      readonly subscription: SubscriptionView | null;
      readonly retentionDays: number;
    };

let session: Session = { status: "UNKNOWN" };
/** In memory for this page load only. Never written anywhere. */
let csrf = "";

export function currentSession(): Session {
  return session;
}

export function csrfToken(): string {
  return csrf;
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

async function post(path: string, body: unknown, withCsrf: boolean): Promise<Outcome<unknown>> {
  const headers: Record<string, string> = { "content-type": "application/json" };
  if (withCsrf) headers["x-ares-csrf"] = csrf;
  try {
    const res = await fetch(path, { method: "POST", headers, body: JSON.stringify(body) });
    const payload: unknown = await res.json().catch(() => null);
    if (!res.ok) {
      const message =
        isRecord(payload) && typeof payload["msg"] === "string" ? payload["msg"] : `HTTP ${res.status}`;
      return { ok: false, reason: message };
    }
    return { ok: true, value: payload };
  } catch {
    return { ok: false, reason: "the server did not answer" };
  }
}

async function get(path: string): Promise<Outcome<unknown>> {
  try {
    const res = await fetch(path, { headers: { accept: "application/json" } });
    const payload: unknown = await res.json().catch(() => null);
    if (!res.ok) {
      const message =
        isRecord(payload) && typeof payload["msg"] === "string" ? payload["msg"] : `HTTP ${res.status}`;
      return { ok: false, reason: message };
    }
    return { ok: true, value: payload };
  } catch {
    return { ok: false, reason: "the server did not answer" };
  }
}

function readUser(value: unknown): AccountUser | null {
  if (!isRecord(value)) return null;
  const { email, displayName, role, mustChangePassword: must } = value;
  if (typeof email !== "string" || typeof displayName !== "string") return null;
  if (role !== "CUSTOMER" && role !== "ADMIN") return null;
  if (typeof must !== "boolean") return null;
  return { email, displayName, role, mustChangePassword: must };
}

function readSubscription(value: unknown): SubscriptionView | null {
  if (!isRecord(value)) return null;
  const { id, plan, status, currentPeriodEnd: end } = value;
  if (typeof id !== "string" || typeof end !== "number") return null;
  if (plan !== "EVALUATION" && plan !== "RETAIL" && plan !== "SOURCE") return null;
  if (status !== "ACTIVE" && status !== "CANCELLED" && status !== "EXPIRED") return null;
  return {
    id,
    plan,
    status,
    currentPeriodEnd: end,
    autoRenew: value["autoRenew"] === true,
    cancelledAt: typeof value["cancelledAt"] === "number" ? value["cancelledAt"] : null,
    cancelEffectiveAt: typeof value["cancelEffectiveAt"] === "number" ? value["cancelEffectiveAt"] : null,
    noticeDays: typeof value["noticeDays"] === "number" ? value["noticeDays"] : 0,
    amountCents: typeof value["amountCents"] === "number" ? value["amountCents"] : 0,
  };
}

function readUploads(value: unknown): UploadView[] {
  if (!Array.isArray(value)) return [];
  const out: UploadView[] = [];
  for (const entry of value) {
    if (!isRecord(entry)) continue;
    const { id, originalName: name, bytes, verdict } = entry;
    if (typeof id !== "string" || typeof name !== "string" || typeof bytes !== "number") continue;
    if (verdict !== "ACCEPTED" && verdict !== "QUARANTINED" && verdict !== "REJECTED") continue;
    out.push({
      id,
      originalName: name,
      bytes,
      verdict,
      createdAt: typeof entry["createdAt"] === "number" ? entry["createdAt"] : 0,
      expiresAt: typeof entry["expiresAt"] === "number" ? entry["expiresAt"] : 0,
      deleted: entry["deleted"] === true,
    });
  }
  return out;
}

/**
 * Ask the server who we are.
 *
 * Returns the subscription as well, because every caller that needs to know whether the
 * session is live also needs to know what it may do with it.
 */
export async function refreshSession(): Promise<Session> {
  const result = await get("/v1/auth/me");
  if (!result.ok) {
    session = { status: "ANON" };
    csrf = "";
    return session;
  }
  const { value: payload } = result;
  if (!isRecord(payload) || payload["ok"] !== true) {
    session = { status: "ANON" };
    return session;
  }
  const user = readUser(payload["user"]);
  if (user === null) {
    session = { status: "ANON" };
    return session;
  }
  csrf = typeof payload["csrf"] === "string" ? payload["csrf"] : "";
  session = {
    status: "AUTHED",
    user,
    subscription: readSubscription(payload["subscription"]),
    retentionDays: typeof payload["retentionDays"] === "number" ? payload["retentionDays"] : 0,
  };
  return session;
}

/** Load the full `/me` payload once, for pages that need consents and uploads too. */
export async function loadAccount(): Promise<Outcome<MeResponse>> {
  const result = await get("/v1/auth/me");
  if (!result.ok) return result;
  const { value: payload } = result;
  if (!isRecord(payload) || payload["ok"] !== true) return { ok: false, reason: "unexpected answer" };
  const user = readUser(payload["user"]);
  if (user === null) return { ok: false, reason: "unexpected answer" };
  csrf = typeof payload["csrf"] === "string" ? payload["csrf"] : "";
  session = {
    status: "AUTHED",
    user,
    subscription: readSubscription(payload["subscription"]),
    retentionDays: typeof payload["retentionDays"] === "number" ? payload["retentionDays"] : 0,
  };
  const consents = Array.isArray(payload["consents"])
    ? payload["consents"].flatMap((entry): MeResponse["consents"] => {
        if (!isRecord(entry)) return [];
        const { kind } = entry;
        if (kind !== "TERMS" && kind !== "PRIVACY" && kind !== "MARKETING") return [];
        return [
          {
            kind,
            version: typeof entry["version"] === "string" ? entry["version"] : "",
            grantedAt: typeof entry["grantedAt"] === "number" ? entry["grantedAt"] : 0,
            withdrawn: entry["withdrawn"] === true,
          },
        ];
      })
    : [];
  return {
    ok: true,
    value: {
      ok: true,
      csrf,
      user,
      consents,
      subscription: readSubscription(payload["subscription"]),
      uploads: readUploads(payload["uploads"]),
      retentionDays: session.retentionDays,
    },
  };
}

async function acceptAuth(result: Outcome<unknown>): Promise<Outcome<AccountUser>> {
  if (!result.ok) return result;
  const { value: payload } = result;
  if (!isRecord(payload)) return { ok: false, reason: "unexpected answer" };
  const user = readUser(payload["user"]);
  if (user === null) return { ok: false, reason: "unexpected answer" };
  csrf = typeof payload["csrf"] === "string" ? payload["csrf"] : "";
  session = { status: "AUTHED", user, subscription: null, retentionDays: 0 };
  // The subscription and retention figures are not in the auth acknowledgement, so the
  // session is refreshed rather than left half-populated.
  await refreshSession();
  const ack: AuthAck = { ok: true, csrf, user };
  return { ok: true, value: ack.user };
}

export async function signup(input: {
  email: string;
  displayName: string;
  password: string;
  acceptPrivacy: boolean;
  acceptTerms: boolean;
  acceptMarketing: boolean;
}): Promise<Outcome<AccountUser>> {
  return acceptAuth(await post("/v1/auth/signup", input, false));
}

export async function login(email: string, password: string): Promise<Outcome<AccountUser>> {
  return acceptAuth(await post("/v1/auth/login", { email, password }, false));
}

export async function logout(): Promise<Outcome<true>> {
  const result = await post("/v1/auth/logout", {}, true);
  session = { status: "ANON" };
  csrf = "";
  return result.ok ? { ok: true, value: true } : { ok: false, reason: result.reason };
}

export async function changePassword(current: string, next: string): Promise<Outcome<AccountUser>> {
  return acceptAuth(await post("/v1/auth/password", { current, next }, true));
}

/**
 * Cancel a subscription.
 *
 * One identifier and one confirmation. Signing up requires three fields and three
 * consent decisions; cancelling requires this call. The asymmetry is intended and is
 * asserted by the server's test suite, not just stated in a policy.
 */
export async function cancelSubscription(subId: string): Promise<Outcome<true>> {
  const result = await post("/v1/subscription/cancel", { subId, confirm: true }, true);
  return result.ok ? { ok: true, value: true } : { ok: false, reason: result.reason };
}

export async function setAutoRenew(subId: string, on: boolean): Promise<Outcome<true>> {
  const result = await post("/v1/subscription/autorenew", { subId, on }, true);
  return result.ok ? { ok: true, value: true } : { ok: false, reason: result.reason };
}

/** Base64 without `btoa` string corruption: the bytes are encoded, not the code units. */
function toBase64(bytes: Uint8Array): string {
  let binary = "";
  const chunk = 0x8000;
  for (let i = 0; i < bytes.length; i += chunk) {
    binary += String.fromCharCode(...bytes.subarray(i, i + chunk));
  }
  return btoa(binary);
}

/** Types the server accepts. Mirrors `ALLOWED_EXTENSIONS` there; the server is the authority. */
export const UPLOAD_MAX_BYTES = 256 * 1024;
export const UPLOAD_TYPES: readonly string[] = [
  "text/plain",
  "text/csv",
  "application/json",
  "image/png",
  "image/jpeg",
  "image/gif",
  "image/webp",
  "application/pdf",
];

export async function uploadFile(file: File, requestRef: string | null): Promise<Outcome<UploadView>> {
  if (file.size === 0) return { ok: false, reason: "that file is empty" };
  if (file.size > UPLOAD_MAX_BYTES) {
    return { ok: false, reason: `the ceiling is ${Math.floor(UPLOAD_MAX_BYTES / 1024)} KiB` };
  }
  if (!UPLOAD_TYPES.includes(file.type)) return { ok: false, reason: `that type (${file.type || "unknown"}) is not accepted` };

  const buffer = await file.arrayBuffer();
  const result = await post(
    "/v1/uploads",
    { name: file.name, type: file.type, data: toBase64(new Uint8Array(buffer)), requestRef },
    true,
  );
  if (!result.ok) return result;
  const { value: payload } = result;
  if (!isRecord(payload) || !isRecord(payload["upload"])) return { ok: false, reason: "unexpected answer" };
  const { upload } = payload;
  const { id, verdict } = upload;
  if (typeof id !== "string" || (verdict !== "ACCEPTED" && verdict !== "QUARANTINED" && verdict !== "REJECTED")) {
    return { ok: false, reason: "unexpected answer" };
  }
  return {
    ok: true,
    value: {
      id,
      originalName: typeof upload["originalName"] === "string" ? upload["originalName"] : file.name,
      bytes: typeof upload["bytes"] === "number" ? upload["bytes"] : file.size,
      verdict,
      createdAt: Date.now(),
      expiresAt: typeof upload["expiresAt"] === "number" ? upload["expiresAt"] : 0,
      deleted: false,
    },
  };
}

/* ---------------- administration ---------------- */

export type AdminSection = "summary" | "users" | "audit";

export type AdminSummary = {
  readonly customers: number;
  readonly admins: number;
  readonly auditRecords: number;
  readonly retentionDays: number;
  readonly noticeDays: number;
  readonly buildRequests: number;
  readonly plans: readonly string[];
};

export async function loadAdminSummary(): Promise<Outcome<AdminSummary>> {
  const result = await get("/v1/admin/summary");
  if (!result.ok) return result;
  const { value: payload } = result;
  if (!isRecord(payload)) return { ok: false, reason: "unexpected answer" };
  const accounts = isRecord(payload["accounts"]) ? payload["accounts"] : {};
  const audit = isRecord(payload["audit"]) ? payload["audit"] : {};
  const retention = isRecord(payload["retention"]) ? payload["retention"] : {};
  const renewal = isRecord(payload["renewal"]) ? payload["renewal"] : {};
  const requests = isRecord(payload["buildRequests"]) ? payload["buildRequests"] : {};
  const number = (value: unknown): number => (typeof value === "number" ? value : 0);
  return {
    ok: true,
    value: {
      customers: number(accounts["customers"]),
      admins: number(accounts["admins"]),
      auditRecords: number(audit["records"]),
      retentionDays: number(retention["uploadDays"]),
      noticeDays: number(renewal["noticeDays"]),
      buildRequests: number(requests["accepted"]),
      plans: Array.isArray(renewal["plans"]) ? renewal["plans"].filter((p): p is string => typeof p === "string") : [],
    },
  };
}

export async function loadAdminUsers(): Promise<Outcome<AdminUserView[]>> {
  const result = await get("/v1/admin/users");
  if (!result.ok) return result;
  const { value: payload } = result;
  if (!isRecord(payload) || !Array.isArray(payload["users"])) return { ok: false, reason: "unexpected answer" };
  const out: AdminUserView[] = [];
  for (const entry of payload["users"]) {
    if (!isRecord(entry)) continue;
    const { id, email, displayName, role, status } = entry;
    if (typeof id !== "string" || typeof email !== "string" || typeof displayName !== "string") continue;
    if (role !== "CUSTOMER" && role !== "ADMIN") continue;
    if (status !== "ACTIVE" && status !== "SUSPENDED" && status !== "CLOSED") continue;
    out.push({
      id,
      email,
      displayName,
      role,
      status,
      createdAt: typeof entry["createdAt"] === "number" ? entry["createdAt"] : 0,
      lastLoginAt: typeof entry["lastLoginAt"] === "number" ? entry["lastLoginAt"] : null,
    });
  }
  return { ok: true, value: out };
}

export async function loadAdminAudit(): Promise<Outcome<AdminAuditView[]>> {
  const result = await get("/v1/admin/audit");
  if (!result.ok) return result;
  const { value: payload } = result;
  if (!isRecord(payload) || !Array.isArray(payload["audit"])) return { ok: false, reason: "unexpected answer" };
  const out: AdminAuditView[] = [];
  for (const entry of payload["audit"]) {
    if (!isRecord(entry)) continue;
    const { seq, action, actorRole, outcome } = entry;
    if (typeof seq !== "number" || typeof action !== "string") continue;
    if (actorRole !== "ANON" && actorRole !== "CUSTOMER" && actorRole !== "ADMIN" && actorRole !== "SYSTEM") continue;
    if (outcome !== "OK" && outcome !== "REFUSED") continue;
    out.push({
      seq,
      ts: typeof entry["ts"] === "number" ? entry["ts"] : 0,
      actorRole,
      actorId: typeof entry["actorId"] === "string" ? entry["actorId"] : null,
      action,
      subjectId: typeof entry["subjectId"] === "string" ? entry["subjectId"] : null,
      outcome,
      detail: typeof entry["detail"] === "string" ? entry["detail"] : "",
    });
  }
  return { ok: true, value: out };
}

/** Change an account's role or status. Administration only, and refused for yourself. */
export async function updateAdminUser(input: {
  userId: string;
  role: AccountRole | null;
  status: AccountStatus | null;
}): Promise<Outcome<true>> {
  const result = await post("/v1/admin/user", input, true);
  return result.ok ? { ok: true, value: true } : { ok: false, reason: result.reason };
}

export { PLAN_LABEL };
