/**
 * Transport primitives, shared by every route module.
 *
 * These were extracted from `http.ts` rather than copied, and the reason is a security
 * one: the origin check, the content-type check and the byte ceiling are the three guards
 * that every write path depends on. Two copies of a guard is two chances for one of them
 * to be edited and the other to keep passing its tests, and the failure mode of that
 * divergence is silent. There is one implementation of each, and every route module
 * imports it.
 *
 * Nothing here makes a decision about authority. This layer moves bytes and refuses
 * malformed ones; who may do what is decided in the route modules and in `auth.ts`.
 */
import type { IncomingMessage, ServerResponse } from "node:http";
import type { ApiErrorCode } from "../shared/protocol.ts";

/**
 * Error code -> HTTP status. One table, so no route can invent a status that disagrees
 * with another route's answer for the same condition.
 */
export const STATUS_OF: Readonly<Record<ApiErrorCode, number>> = {
  BAD_METHOD: 405,
  BAD_CT: 415,
  TOO_LARGE: 413,
  MALFORMED: 400,
  SCHEMA: 400,
  SIG: 401,
  ROLE: 403,
  REPLAY: 409,
  RATE: 429,
  STALE: 400,
  FORBIDDEN: 403,
  NOT_FOUND: 404,
};

/**
 * Headers emitted on every response.
 *
 * `default-src 'none'` plus an explicit `script-src 'self'` is what makes a stored-XSS
 * payload inert: there is no inline script to inject into, no third-party origin to load
 * from, and no `object` or `base` to abuse. `form-action 'none'` means a form cannot
 * navigate a submission anywhere, so the only way a payload leaves this origin is through
 * the same-origin fetches the pages already make. `frame-ancestors 'none'` blocks click
 * jacking of the console, and `Cross-Origin-Resource-Policy` stops the responses being
 * read by another origin even when they are cached.
 *
 * `font-src 'self'` is explicit rather than inherited, and that matters: the landing page
 * serves Space Grotesk and JetBrains Mono from this origin instead of a font host, so a
 * missing directive would not fail loudly — it would fall back to `default-src 'none'`,
 * block the .woff2 files, and leave the page rendering in whatever the system picked. A
 * directive that is absent looks exactly like a directive that is satisfied.
 */
export const SECURITY_HEADERS: Readonly<Record<string, string>> = {
  "X-Content-Type-Options": "nosniff",
  "Referrer-Policy": "no-referrer",
  "X-Frame-Options": "DENY",
  "Cross-Origin-Opener-Policy": "same-origin",
  "Cross-Origin-Resource-Policy": "same-origin",
  "Permissions-Policy": "camera=(), microphone=(), geolocation=(), payment=()",
  "Strict-Transport-Security": "max-age=31536000; includeSubDomains",
  "Content-Security-Policy":
    "default-src 'none'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; font-src 'self'; connect-src 'self'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'; object-src 'none'",
};

export type BodyResult =
  | { readonly ok: true; readonly body: string }
  | { readonly ok: false; readonly reason: "TOO_LARGE" | "ABORTED" };

export function send(res: ServerResponse, status: number, body: string, type: string, head = false): void {
  if (res.writableEnded) return;
  res.writeHead(status, {
    "Content-Type": type,
    // Nothing this process returns may be cached: every response is either credentials,
    // account data or live telemetry.
    "Cache-Control": "no-store, no-cache, must-revalidate",
    ...SECURITY_HEADERS,
  });
  res.end(head ? undefined : body);
}

export function json(res: ServerResponse, status: number, value: unknown): void {
  send(res, status, JSON.stringify(value), "application/json; charset=utf-8");
}

export function fail(res: ServerResponse, status: number, code: ApiErrorCode, msg: string): void {
  json(res, status, { e: code, msg });
}

export function header(req: IncomingMessage, name: string): string | null {
  const value = req.headers[name];
  if (typeof value === "string") return value;
  if (Array.isArray(value) && value.length > 0) return value[0] ?? null;
  return null;
}

/**
 * Read a body under a hard ceiling.
 *
 * Overflow is answered before the whole body has been received: the caller replies 413
 * and destroys the socket. A ceiling checked after buffering is not a ceiling, it is a
 * report of how much memory an attacker already used.
 */
export function readBody(req: IncomingMessage, cap: number): Promise<BodyResult> {
  return new Promise((resolve) => {
    let settled = false;
    let size = 0;
    const chunks: Buffer[] = [];

    const finish = (result: BodyResult): void => {
      if (settled) return;
      settled = true;
      req.removeListener("data", onData);
      resolve(result);
    };

    const onData = (chunk: Buffer): void => {
      size += chunk.length;
      if (size > cap) {
        finish({ ok: false, reason: "TOO_LARGE" });
        req.pause();
        return;
      }
      chunks.push(chunk);
    };

    req.on("data", onData);
    req.on("end", () => finish({ ok: true, body: Buffer.concat(chunks).toString("utf8") }));
    req.on("aborted", () => finish({ ok: false, reason: "ABORTED" }));
    req.on("error", () => finish({ ok: false, reason: "ABORTED" }));
  });
}

/**
 * Same-origin enforcement, in one place.
 *
 * A non-browser principal sends no `Origin` and is allowed through: it is not a browser,
 * so it has no ambient credentials to be tricked into spending, and the signed agent
 * fleet depends on that. A browser that names an origin is allowed only if that origin
 * was configured. No CORS headers are ever emitted, so an allowed origin still cannot
 * read a response cross-origin — the check admits the request, it does not grant access.
 */
export function originAllowed(req: IncomingMessage, allowed: readonly string[]): boolean {
  const origin = req.headers.origin;
  if (typeof origin !== "string") return true;
  return allowed.includes(origin);
}

/** Every write path requires `application/json`. `text/plain` and form encodings are refused. */
export function jsonContentType(req: IncomingMessage): boolean {
  const ctype = header(req, "content-type");
  if (ctype === null) return false;
  return ctype.toLowerCase().startsWith("application/json");
}

/**
 * The source identity a velocity gate is charged against.
 *
 * The socket address is used by default, because `x-forwarded-for` is a claim and any
 * caller can make it. It is only consulted when the operator has stated that a reverse
 * proxy sits in front of this process; then the RIGHTMOST entry is taken, since that is
 * the hop the trusted proxy itself appended. Trusting the leftmost entry — the usual
 * mistake — lets a caller choose its own bucket key and defeat the limit entirely.
 */
export function sourceOf(req: IncomingMessage): string {
  const socket = req.socket.remoteAddress ?? "unknown";
  if (process.env["ARES_TRUST_PROXY"] !== "1") return socket;
  const forwarded = header(req, "x-forwarded-for");
  if (forwarded === null) return socket;
  const parts = forwarded.split(",");
  const last = parts[parts.length - 1];
  return last === undefined || last.trim() === "" ? socket : last.trim();
}

export function constantTimeEqual(a: string, b: string): boolean {
  const len = Math.max(a.length, b.length);
  let diff = a.length ^ b.length;
  for (let i = 0; i < len; i += 1) {
    diff |= (a.charCodeAt(i) || 0) ^ (b.charCodeAt(i) || 0);
  }
  return diff === 0;
}

/** Append a `Set-Cookie` without discarding one that is already queued. */
export function addCookie(res: ServerResponse, cookie: string): void {
  const existing = res.getHeader("Set-Cookie");
  if (existing === undefined) {
    res.setHeader("Set-Cookie", cookie);
    return;
  }
  if (Array.isArray(existing)) {
    res.setHeader("Set-Cookie", [...existing, cookie]);
    return;
  }
  res.setHeader("Set-Cookie", [String(existing), cookie]);
}
import "./legacy-env.ts";
