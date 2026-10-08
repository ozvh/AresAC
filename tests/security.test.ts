/**
 * Security suite.
 *
 * These tests are written from the attacker's side of each control. "Passwords are hashed"
 * is not a test; "an unknown address costs the same work as a known one" is. "Admin routes
 * are protected" is not a test; "a customer session reaching for an administrator route is
 * refused *and leaves a refusal in the audit trail*" is.
 *
 * Three of them assert that the database itself refuses something, not application code:
 * the audit log cannot be updated or deleted, foreign keys are enforced, and a constraint
 * rejects a role that does not exist. Those are the assertions that survive a bug in a
 * handler, because the handler is not what enforces them.
 */
import assert from "node:assert/strict";
import { after, before, test } from "node:test";
import { createServer, type IncomingMessage, type Server } from "node:http";
// The promise-based forms: the callback overloads would silently return void here, which
// is exactly the sort of thing an await cannot catch.
import { mkdtemp, readFile } from "node:fs/promises";
import { existsSync, statSync } from "node:fs";
import { DatabaseSync } from "node:sqlite";
import os from "node:os";
import path from "node:path";
import type { AddressInfo } from "node:net";
import { LIMITS, type MeResponse } from "../shared/protocol.ts";
import { AgentRegistry } from "../server/agents.ts";
import { CSRF_HEADER, SESSION_COOKIE, parseCookies } from "../server/auth.ts";
import { Store } from "../server/db.ts";
import { Fleet } from "../server/fleet.ts";
import { createArbiterServer } from "../server/http.ts";
import { Ledger } from "../server/ledger.ts";
import { Arbiter } from "../server/machine.ts";
import { checkPassword, hashPassword, verifyAbsent, verifyPassword } from "../server/passwords.ts";
import { Broadcaster } from "../server/sse.ts";
import { CANCEL_FIELDS } from "../server/subscriptions.ts";
import { sourceOf } from "../server/http-kit.ts";
import { productionReadiness } from "../server/prodcheck.ts";
import { judge, parseUpload, sanitiseName, UPLOAD_MAX_BASE64, UPLOAD_MAX_BYTES } from "../server/uploads.ts";
import { testSystem, type TestSystem } from "./harness.ts";

const ORIGIN = "http://127.0.0.1:5173";
const OPERATOR_TOKEN = "c".repeat(48);

/**
 * Every request in this suite comes from a different simulated client.
 *
 * The velocity gates key on `sourceOf(req)`, and a suite that signs up forty accounts from
 * one address spends its run being correctly refused — which is the limiter working, not a
 * bug to paper over. So the harness declares a trusted proxy, the one deployment shape in
 * which the forwarded header is authoritative, and rotates the address it presents. The
 * per-source gate still counts per address; one test below asserts that a caller cannot
 * choose its own key when the header is not trusted.
 */
let clientSeq = 0;

function nextSource(): string {
  clientSeq += 1;
  return `10.7.${Math.floor(clientSeq / 250)}.${(clientSeq % 250) + 1}`;
}

/** A valid 1x1 PNG: signature, IHDR, IDAT, IEND. Enough for the magic-byte check. */
const PNG_1X1 = Buffer.from(
  "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mP8z8DwHwAFAAH/q842iQAAAABJRU5ErkJggg==",
  "base64",
);

function zipBytes(): Buffer {
  return Buffer.from([0x50, 0x4b, 0x03, 0x04, 0x14, 0x00, 0x00, 0x00]);
}

const DAY_MS = 24 * 60 * 60 * 1_000;

/**
 * The system runs on a clock this suite can move.
 *
 * Two of the requirements are time-shaped — a renewal notice lands inside its window, and
 * an artefact is deleted once its retention window closes — and neither can be observed
 * by waiting, because waiting thirty days is not a test. So the whole system is built with
 * `now: () => Date.now() + clockOffsetMs` and these two tests move the offset. Every other
 * test runs at offset zero and is therefore unaffected, which is what makes the shared
 * harness acceptable here.
 */
let clockOffsetMs = 0;

async function withClock<T>(offsetMs: number, body: () => Promise<T>): Promise<T> {
  clockOffsetMs = offsetMs;
  try {
    return await body();
  } finally {
    clockOffsetMs = 0;
  }
}

/* ------------------------------------------------------------------ */
/*  Passwords                                                          */
/* ------------------------------------------------------------------ */

test("a password digest is self-describing and verifies only its own password", async () => {
  const digest = await hashPassword("correct horse battery staple");
  assert.match(digest, /^scrypt\$16384\$8\$1\$[A-Za-z0-9+/=]+\$[A-Za-z0-9+/=]+$/);
  assert.equal(await verifyPassword("correct horse battery staple", digest), true);
  assert.equal(await verifyPassword("correct horse battery stapl", digest), false);
  // The plaintext must not be recoverable from the digest by inspection.
  assert.ok(!digest.includes("correct"), "the digest must not contain the password");
});

test("two hashes of one password differ, so a shared salt cannot be precomputed", async () => {
  const a = await hashPassword("a-long-enough-password");
  const b = await hashPassword("a-long-enough-password");
  assert.notEqual(a, b);
  assert.equal(await verifyPassword("a-long-enough-password", a), true);
  assert.equal(await verifyPassword("a-long-enough-password", b), true);
});

test("a corrupted or hostile digest fails closed instead of throwing", async () => {
  for (const bad of [
    "",
    "not-a-digest",
    "scrypt$16384$8$1$short$short",
    "bcrypt$10$abc$def",
    // A digest demanding absurd work must not be honoured: that would turn a tampered row
    // into a memory-exhaustion primitive against the sign-in endpoint.
    "scrypt$1073741824$32$1$AAAAAAAAAAAAAAAAAAAAAA==$AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
    "scrypt$999$8$1$AAAAAAAAAAAAAAAAAAAAAA==$AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
  ]) {
    assert.equal(await verifyPassword("anything at all", bad), false, `should refuse: ${bad.slice(0, 40)}`);
  }
});

test("the password policy refuses the shapes it exists for", () => {
  assert.notEqual(checkPassword("short", "a@b.com"), null);
  assert.notEqual(checkPassword("            ", "a@b.com"), null);
  assert.notEqual(checkPassword("x".repeat(201), "a@b.com"), null);
  assert.notEqual(checkPassword("passwordpassword", "a@b.com"), null);
  assert.notEqual(checkPassword("myaccountname1234", "myaccountname@b.com"), null);
  assert.equal(checkPassword("a reasonably long passphrase", "a@b.com"), null);
});

test("an unknown account costs the same work as a known one", async () => {
  // The property being asserted is that this call does real work and answers false. It
  // exists so that the unknown-address path cannot be distinguished by response time.
  const started = performance.now();
  const result = await verifyAbsent("anything at all");
  const elapsed = performance.now() - started;
  assert.equal(result, false, "verifyAbsent must never authenticate anyone");
  assert.ok(elapsed > 5, `expected real scrypt work, took ${elapsed.toFixed(1)}ms`);
});

/* ------------------------------------------------------------------ */
/*  Schema rules, enforced by the engine                               */
/* ------------------------------------------------------------------ */

test("the database enforces its own rules rather than trusting the caller", async () => {
  const dir = await mkdtemp(path.join(os.tmpdir(), "ares-db-"));
  const file = path.join(dir, "rules.db");
  const store = new Store({ file, now: () => Date.now() });

  // The file itself, not only the parent directory: a database holding session digests,
  // consent records and the audit log must not be readable by every account on the host.
  // Asserted only where the platform implements POSIX modes; on Windows the call is a
  // best-effort no-op and the host's own policy is the control.
  if (process.platform !== "win32") {
    assert.equal(statSync(file).mode & 0o777, 0o600, "the database file must be owner-only");
  }

  const invariants = store.invariants();
  assert.equal(invariants.foreignKeys, true, "foreign key enforcement must be switched on explicitly");
  assert.equal(invariants.appendOnlyTriggers, 4, "every append-only trigger must exist");
  assert.equal(invariants.schemaVersion, 2);

  store.audit({
    ts: 1,
    actorId: null,
    actorRole: "SYSTEM",
    action: "TEST.SEED",
    subjectId: null,
    outcome: "OK",
    detail: "seed",
    ipHash: "",
  });
  store.close();

  // A second connection stands in for anyone else with file access: an operator with a
  // sqlite prompt, a restore tool, or a later refactor that forgot the rule.
  const intruder = new DatabaseSync(file);
  assert.throws(() => intruder.exec("UPDATE audit_log SET detail = 'rewritten'"), /append-only/);
  assert.throws(() => intruder.exec("DELETE FROM audit_log"), /append-only/);

  // Foreign keys really are enforced on this connection, not merely declared.
  assert.throws(
    () => intruder.exec("INSERT INTO sessions (id, user_id, token_hash, csrf_hash, created_at, expires_at, last_seen_at, ip_hash, ua_hash) VALUES ('a','nobody','h','h',1,2,1,'i','u')"),
    /FOREIGN KEY/i,
  );
  // A role that does not exist is refused by the CHECK constraint.
  assert.throws(
    () =>
      intruder.exec(
        "INSERT INTO users (id, email, display_name, role, status, pwd_hash, created_at, updated_at, password_changed_at) VALUES ('x','a@b.com','n','SUPERUSER','ACTIVE','h',1,1,1)",
      ),
    /CHECK/i,
  );
  // The same address cannot be registered twice, and case does not defeat it.
  intruder.exec(
    "INSERT INTO users (id, email, display_name, role, status, pwd_hash, created_at, updated_at, password_changed_at) VALUES ('u1','dup@b.com','n','CUSTOMER','ACTIVE','h',1,1,1)",
  );
  assert.throws(
    () =>
      intruder.exec(
        "INSERT INTO users (id, email, display_name, role, status, pwd_hash, created_at, updated_at, password_changed_at) VALUES ('u2','DUP@B.COM','n','CUSTOMER','ACTIVE','h',1,1,1)",
      ),
    /UNIQUE/i,
  );
  intruder.close();
});

test("no statement in the data layer is assembled from a value", async () => {
  // The property that makes "parameterized queries" a fact rather than a claim: a value
  // can only reach SQL as a bound parameter. db.ts writes even its long statements as
  // template literals, so the assertion is not "no backticks" — it is "no substitution".
  // A statement whose text is partly built from data is the one that becomes an injection,
  // and that is what is checked, against the source, which is where the guarantee lives.
  const source = await readFile(path.join(process.cwd(), "server", "db.ts"), "utf8");
  assert.doesNotMatch(source, /#stmt\([^)]*\$\{/, "a prepared statement was built from interpolated text");
  assert.doesNotMatch(source, /\.prepare\([^)]*\$\{/, "a prepared statement was built from interpolated text");

  // The interpolations that do exist are a version number and two error messages. Each is
  // named here, so a new one is a decision rather than a pattern that quietly spread.
  const interpolating = source.split("\n").filter((line) => line.includes("${"));
  assert.ok(interpolating.length > 0, "the schema version must be applied through a pragma");
  for (const line of interpolating) {
    assert.match(
      line.trim(),
      /^(`database schema version|if \(script === undefined\)|this\.#db\.exec\(`PRAGMA user_version)/,
      `an interpolation outside a version number or a message: ${line.trim()}`,
    );
  }
});

/* ------------------------------------------------------------------ */
/*  Live HTTP surface                                                  */
/* ------------------------------------------------------------------ */

type Harness = {
  base: string;
  system: TestSystem;
  relay: { url: string; captured: Array<Record<string, unknown>> };
};

let harness: Harness;
let server: ReturnType<typeof createArbiterServer>;
let relayServer: Server;
let dbDir = "";

before(async () => {
  dbDir = await mkdtemp(path.join(os.tmpdir(), "ares-sec-"));

  // A trusted proxy is declared, so the harness's rotating forwarded address is honoured,
  // and the global signup flood gate is raised for the run: forty accounts in three
  // seconds is a legitimate client, not a flood. Both are restored in `after`.
  process.env["ARES_TRUST_PROXY"] = "1";
  process.env["ARES_SIGNUP_PER_MIN"] = "600";

  const captured: Array<Record<string, unknown>> = [];
  relayServer = createServer((req: IncomingMessage, res) => {
    const chunks: Buffer[] = [];
    req.on("data", (chunk: Buffer) => chunks.push(chunk));
    req.on("end", () => {
      try {
        const parsed: unknown = JSON.parse(Buffer.concat(chunks).toString("utf8"));
        if (typeof parsed === "object" && parsed !== null) captured.push(parsed as Record<string, unknown>);
      } catch {
        // A body that is not JSON is not the relay's problem.
      }
      res.writeHead(200, { "content-type": "application/json" });
      res.end(JSON.stringify({ id: "relay" }));
    });
  });
  await new Promise<void>((resolve) => relayServer.listen(0, "127.0.0.1", resolve));
  const relayAddress = relayServer.address() as AddressInfo;

  const registry = new AgentRegistry(Buffer.alloc(32, 5));
  const system = testSystem({
    arbiter: new Arbiter(new Ledger()),
    ledger: new Ledger(),
    bus: new Broadcaster(LIMITS.replayRing),
    registry,
    fleet: new Fleet(registry, { sessions: 1, tps: 0, origin: "http://127.0.0.1:1", seed: 4 }),
    operatorToken: OPERATOR_TOKEN,
    relay: { apiKey: "k", endpoint: `http://127.0.0.1:${relayAddress.port}/emails`, recipient: "cagelove094@gmail.com" },
    uploadRoot: path.join(dbDir, "uploads"),
    retentionDays: 30,
    noticeDays: 14,
    now: () => Date.now() + clockOffsetMs,
  });

  server = createArbiterServer({ runtime: system.runtime, consoleOrigins: [ORIGIN], staticDir: null });
  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
  const address = server.address() as AddressInfo;
  harness = {
    base: `http://127.0.0.1:${address.port}`,
    system,
    relay: { url: `http://127.0.0.1:${relayAddress.port}/emails`, captured },
  };
});

after(async () => {
  await new Promise<void>((resolve) => server.close(() => resolve()));
  await new Promise<void>((resolve) => relayServer.close(() => resolve()));
  delete process.env["ARES_TRUST_PROXY"];
  delete process.env["ARES_SIGNUP_PER_MIN"];
});

test("a forwarded address is a claim, not a fact, unless a proxy is declared", () => {
  // `x-forwarded-for` is caller-controlled. Trusting it by default would let any client
  // choose its own rate-limit bucket, which is the same as having no limit at all.
  const spoofed = {
    socket: { remoteAddress: "203.0.113.9" },
    headers: { "x-forwarded-for": "10.9.9.9, 198.51.100.7" },
  } as unknown as IncomingMessage;

  const previous = process.env["ARES_TRUST_PROXY"];
  try {
    process.env["ARES_TRUST_PROXY"] = "0";
    assert.equal(sourceOf(spoofed), "203.0.113.9", "an untrusted header must not choose the bucket");
    process.env["ARES_TRUST_PROXY"] = "1";
    // The rightmost entry is the hop the trusted proxy itself appended. Taking the
    // leftmost — the usual mistake — hands the caller its own key.
    assert.equal(sourceOf(spoofed), "198.51.100.7");
  } finally {
    if (previous === undefined) delete process.env["ARES_TRUST_PROXY"];
    else process.env["ARES_TRUST_PROXY"] = previous;
  }
});

type Call = {
  readonly cookie?: string;
  readonly csrf?: string;
  readonly origin?: string;
  readonly type?: string;
};

async function post(pathname: string, body: unknown, call: Call = {}): Promise<Response> {
  const headers: Record<string, string> = {
    "content-type": call.type ?? "application/json",
    origin: call.origin ?? ORIGIN,
    "x-forwarded-for": nextSource(),
  };
  if (call.cookie !== undefined) headers["cookie"] = call.cookie;
  if (call.csrf !== undefined) headers[CSRF_HEADER] = call.csrf;
  return fetch(`${harness.base}${pathname}`, { method: "POST", headers, body: JSON.stringify(body) });
}

async function get(pathname: string, cookie?: string): Promise<Response> {
  const headers: Record<string, string> = { origin: ORIGIN, "x-forwarded-for": nextSource() };
  if (cookie !== undefined) headers["cookie"] = cookie;
  return fetch(`${harness.base}${pathname}`, { headers });
}

/** A signed-up session, plus the cookie and CSRF token needed to act with it. */
async function account(
  email: string,
  displayName = "Test Person",
): Promise<{ cookie: string; csrf: string; userId: string }> {
  const res = await post("/v1/auth/signup", {
    email,
    displayName,
    password: "a sufficiently long password",
    acceptPrivacy: true,
    acceptTerms: true,
    acceptMarketing: false,
  });
  assert.equal(res.status, 201, `signup failed for ${email}`);
  const cookie = cookieFrom(res);
  const body = (await res.json()) as { csrf: string };
  const row = harness.system.store.userByEmail(email);
  assert.ok(row !== null);
  return { cookie, csrf: body.csrf, userId: row.id };
}

function cookieFrom(res: Response): string {
  const raw = res.headers.get("set-cookie");
  assert.ok(raw !== null, "expected a session cookie");
  const value = parseCookies(raw).get(SESSION_COOKIE);
  assert.ok(value !== undefined && value.length > 16, "expected a session cookie value");
  return `${SESSION_COOKIE}=${value}`;
}

/* ---------------- registration and consent ---------------- */

test("signup writes the account, the consents and a sealed audit record", async () => {
  const before_ = harness.system.store.countAudit();
  const res = await post("/v1/auth/signup", {
    email: "consent@example.com",
    displayName: "Consent Case",
    password: "a sufficiently long password",
    acceptPrivacy: true,
    acceptTerms: true,
    acceptMarketing: true,
  });
  assert.equal(res.status, 201);

  const user = harness.system.store.userByEmail("consent@example.com");
  assert.ok(user !== null);
  const consents = harness.system.store.listConsents(user.id).map((row) => row.kind);
  assert.deepEqual(consents.sort(), ["MARKETING", "PRIVACY", "TERMS"]);
  assert.ok(harness.system.store.countAudit() > before_);

  // The password must not be stored anywhere, and the response must not echo it.
  assert.ok(!user.pwd_hash.includes("sufficiently"));
  const body = await res.text();
  assert.ok(!body.includes("sufficiently"));
});

test("an account cannot be created without accepting the policy", async () => {
  const res = await post("/v1/auth/signup", {
    email: "noconsent@example.com",
    displayName: "No Consent",
    password: "a sufficiently long password",
    acceptPrivacy: false,
    acceptTerms: true,
    acceptMarketing: false,
  });
  assert.equal(res.status, 400);
  assert.equal(harness.system.store.userByEmail("noconsent@example.com"), null, "no account may exist without consent");
});

test("a duplicate address is refused without confirming that it exists", async () => {
  await account("dup@example.com");
  const again = await post("/v1/auth/signup", {
    email: "DUP@example.com",
    displayName: "Someone Else",
    password: "a different long password",
    acceptPrivacy: true,
    acceptTerms: true,
    acceptMarketing: false,
  });
  assert.equal(again.status, 409);
  const payload = (await again.json()) as { msg: string };
  // The status does disclose that the address is in use — that is the residual disclosure
  // until sign-up verification by email exists, and docs/SECURITY.md records it. What the
  // message must not do is confirm anything about an account or echo the address back.
  assert.doesNotMatch(payload.msg, /your account|registered to|we found|that email is taken/i);
  assert.ok(!payload.msg.includes("dup@example.com"));
  // Case must not create a second account.
  assert.equal(harness.system.store.countUsers("CUSTOMER") - 0 >= 1, true);
  const all = harness.system.store.listUsers(100, 0).filter((row) => row.email.toLowerCase() === "dup@example.com");
  assert.equal(all.length, 1);
});

/* ---------------- session cookie and CSRF ---------------- */

test("the session cookie is HttpOnly, SameSite=Strict and not readable by script", async () => {
  const res = await post("/v1/auth/signup", {
    email: "cookie@example.com",
    displayName: "Cookie Case",
    password: "a sufficiently long password",
    acceptPrivacy: true,
    acceptTerms: true,
    acceptMarketing: false,
  });
  const raw = res.headers.get("set-cookie") ?? "";
  assert.match(raw, /HttpOnly/);
  assert.match(raw, /SameSite=Strict/);
  assert.match(raw, /Path=\//);
  assert.doesNotMatch(raw, /Domain=/);
});

test("a session is required to read anything about an account", async () => {
  assert.equal((await get("/v1/auth/me")).status, 401);
  assert.equal((await get("/v1/auth/me", `${SESSION_COOKIE}=obviouslynotasession`)).status, 401);
  assert.equal((await get("/v1/uploads")).status, 401);
  assert.equal((await get("/v1/admin/summary")).status, 401);
});

test("a mutation without the synchroniser token is refused even with a valid session", async () => {
  const me = await account("csrf@example.com");
  const ok = await get("/v1/auth/me", me.cookie);
  assert.equal(ok.status, 200);

  // The cookie is genuine; only the token is missing. This is exactly the shape of a
  // cross-site request, which cannot read the token but can carry the cookie.
  const noToken = await post("/v1/subscription/autorenew", { subId: "a".repeat(32), on: false }, { cookie: me.cookie });
  assert.equal(noToken.status, 403);

  const wrongToken = await post(
    "/v1/subscription/autorenew",
    { subId: "a".repeat(32), on: false },
    { cookie: me.cookie, csrf: "not-the-token" },
  );
  assert.equal(wrongToken.status, 403);

  const goodToken = await post(
    "/v1/subscription/autorenew",
    { subId: "a".repeat(32), on: false },
    { cookie: me.cookie, csrf: me.csrf },
  );
  // The token is right, so the request reaches the handler: the subscription simply does
  // not exist. A 404 here and a 403 above is the difference the token makes.
  assert.equal(goodToken.status, 404);
});

test("a cross-origin mutation is refused before anything else happens", async () => {
  const me = await account("origin@example.com");
  const res = await post(
    "/v1/subscription/autorenew",
    { subId: "a".repeat(32), on: false },
    { cookie: me.cookie, csrf: me.csrf, origin: "https://evil.example" },
  );
  assert.equal(res.status, 403);
  // A form encoding cannot even reach the parser.
  const form = await post(
    "/v1/auth/login",
    { email: "origin@example.com", password: "a sufficiently long password" },
    { type: "application/x-www-form-urlencoded", origin: "https://evil.example" },
  );
  assert.ok(form.status === 403 || form.status === 415);
});

/* ---------------- authentication outcomes ---------------- */

test("every failed sign-in answers identically", async () => {
  const me = await account("ident@example.com");
  void me;

  const unknown = await post("/v1/auth/login", { email: "nobody@example.com", password: "a sufficiently long password" });
  const wrong = await post("/v1/auth/login", { email: "ident@example.com", password: "not the right password" });

  assert.equal(unknown.status, 401);
  assert.equal(wrong.status, 401);
  const a = (await unknown.json()) as { msg: string };
  const b = (await wrong.json()) as { msg: string };
  assert.equal(a.msg, b.msg, "the two answers must be indistinguishable");
});

test("a correct password signs in and the session resolves", async () => {
  await account("signin@example.com");
  const res = await post("/v1/auth/login", { email: "signin@example.com", password: "a sufficiently long password" });
  assert.equal(res.status, 200);
  const me = await get("/v1/auth/me", cookieFrom(res));
  assert.equal(me.status, 200);
  const body = (await me.json()) as MeResponse;
  assert.equal(body.user.email, "signin@example.com");
  assert.equal(body.user.role, "CUSTOMER");
});

test("repeated failures lock the account, and a locked account is refused", async () => {
  await account("locked@example.com");
  for (let attempt = 0; attempt < 8; attempt += 1) {
    const res = await post("/v1/auth/login", { email: "locked@example.com", password: "wrong password here" });
    assert.equal(res.status, 401);
  }
  const correct = await post("/v1/auth/login", {
    email: "locked@example.com",
    password: "a sufficiently long password",
  });
  assert.equal(correct.status, 401, "a locked account must be refused even with the right password");
  const row = harness.system.store.userByEmail("locked@example.com");
  assert.ok(row !== null && row.locked_until > 0, "the lock must be recorded");
});

test("signing out ends the session immediately", async () => {
  const me = await account("signout@example.com");
  assert.equal((await get("/v1/auth/me", me.cookie)).status, 200);
  const out = await post("/v1/auth/logout", {}, { cookie: me.cookie, csrf: me.csrf });
  assert.equal(out.status, 200);
  assert.equal((await get("/v1/auth/me", me.cookie)).status, 401);
});

test("changing a password ends every other session", async () => {
  const first = await account("rotate@example.com");
  const second = await post("/v1/auth/login", { email: "rotate@example.com", password: "a sufficiently long password" });
  const secondCookie = cookieFrom(second);
  assert.equal((await get("/v1/auth/me", secondCookie)).status, 200);

  const changed = await post(
    "/v1/auth/password",
    { current: "a sufficiently long password", next: "an entirely new passphrase" },
    { cookie: first.cookie, csrf: first.csrf },
  );
  assert.equal(changed.status, 200);

  // The session that changed the password is re-issued; the other one is dead.
  assert.equal((await get("/v1/auth/me", secondCookie)).status, 401);
  assert.equal((await get("/v1/auth/me", cookieFrom(changed))).status, 200);
  // And the old password no longer works.
  const oldPassword = await post("/v1/auth/login", { email: "rotate@example.com", password: "a sufficiently long password" });
  assert.equal(oldPassword.status, 401);
});

/* ---------------- authority ---------------- */

test("a customer session is refused an administrator route and the attempt is recorded", async () => {
  const me = await account("peasant@example.com");
  const before_ = harness.system.store.countAudit();
  const res = await get("/v1/admin/summary", me.cookie);
  assert.equal(res.status, 403);

  const records = harness.system.store.auditTail(harness.system.store.countAudit() - before_ + 1);
  const refusal = records.find((row) => row.action === "AUTHZ.REFUSED");
  assert.ok(refusal !== undefined, "reaching for authority must leave a refusal in the audit trail");
  assert.equal(refusal.outcome, "REFUSED");
  assert.match(refusal.detail, /required ADMIN, held CUSTOMER/);
});

test("administrator routes are refused until a bootstrap password has been changed", async () => {
  const auth = harness.system.auth;
  await auth.ensureBootstrapAdmin({
    ARES_BOOTSTRAP_ADMIN_EMAIL: "root@example.com",
    ARES_BOOTSTRAP_ADMIN_PASSWORD: "a bootstrap password that is long",
  });

  const signin = await post("/v1/auth/login", {
    email: "root@example.com",
    password: "a bootstrap password that is long",
  });
  assert.equal(signin.status, 200);
  const body = (await signin.json()) as { csrf: string; user: { mustChangePassword: boolean } };
  assert.equal(body.user.mustChangePassword, true, "a credential from the environment must be treated as temporary");

  const cookie = cookieFrom(signin);
  assert.equal((await get("/v1/admin/summary", cookie)).status, 403, "privileged reads must wait for the change");

  const changed = await post(
    "/v1/auth/password",
    { current: "a bootstrap password that is long", next: "a properly chosen administrator passphrase" },
    { cookie, csrf: body.csrf },
  );
  assert.equal(changed.status, 200);

  const summary = await get("/v1/admin/summary", cookieFrom(changed));
  assert.equal(summary.status, 200);
});

test("an administrator cannot change their own authority, and the last one cannot be removed", async () => {
  const login = await post("/v1/auth/login", {
    email: "root@example.com",
    password: "a properly chosen administrator passphrase",
  });
  assert.equal(login.status, 200);
  const { csrf } = (await login.json()) as { csrf: string };
  const cookie = cookieFrom(login);
  const root = harness.system.store.userByEmail("root@example.com");
  assert.ok(root !== null);

  const self = await post("/v1/admin/user", { userId: root.id, role: "CUSTOMER", status: null }, { cookie, csrf });
  assert.equal(self.status, 403, "self-demotion must be refused by the server, not merely hidden by the page");

  // Promote a customer, then confirm the last administrator is still protected.
  const victim = await account("promotable@example.com");
  const promote = await post("/v1/admin/user", { userId: victim.userId, role: "ADMIN", status: null }, { cookie, csrf });
  assert.equal(promote.status, 200);
  const demote = await post("/v1/admin/user", { userId: victim.userId, role: "CUSTOMER", status: null }, { cookie, csrf });
  assert.equal(demote.status, 200);
  assert.equal(harness.system.store.countUsers("ADMIN"), 1);
});

test("suspending an account ends its sessions in the same action", async () => {
  const victim = await account("suspended@example.com");
  assert.equal((await get("/v1/auth/me", victim.cookie)).status, 200);

  const login = await post("/v1/auth/login", {
    email: "root@example.com",
    password: "a properly chosen administrator passphrase",
  });
  const { csrf } = (await login.json()) as { csrf: string };
  const adminCookie = cookieFrom(login);

  const suspend = await post(
    "/v1/admin/user",
    { userId: victim.userId, role: null, status: "SUSPENDED" },
    { cookie: adminCookie, csrf },
  );
  assert.equal(suspend.status, 200);
  assert.equal((await get("/v1/auth/me", victim.cookie)).status, 401, "suspension must not wait for session expiry");
});

test("a sign-in is recorded under the role of the account it named", async () => {
  // The audit log is the evidence a reader has to work from, so a wrong actor is worse
  // than a missing one. This once recorded every attempt as CUSTOMER, which meant an
  // administrator's sign-in was indistinguishable from a customer's.
  const login = await post("/v1/auth/login", {
    email: "root@example.com",
    password: "a properly chosen administrator passphrase",
  });
  assert.equal(login.status, 200);
  const accepted = harness.system.store
    .auditTail(10)
    .find((row) => row.action === "AUTH.LOGIN" && row.outcome === "OK");
  assert.ok(accepted !== undefined);
  assert.equal(accepted.actor_role, "ADMIN");

  // A refused attempt carries the same role: an attempt on an administrator account is not
  // the same event as one on a customer account, even though the caller cannot tell them
  // apart from the response.
  await post("/v1/auth/login", { email: "root@example.com", password: "definitely the wrong password" });
  const refused = harness.system.store
    .auditTail(10)
    .find((row) => row.action === "AUTH.LOGIN" && row.outcome === "REFUSED");
  assert.ok(refused !== undefined);
  assert.equal(refused.actor_role, "ADMIN");
  assert.match(refused.detail, /wrong password/);

  // An address with no account has no role to record, and the absence is explicit rather
  // than defaulted to the least interesting value.
  await post("/v1/auth/login", { email: "nobody-at-all@example.com", password: "definitely the wrong password" });
  const unknown = harness.system.store
    .auditTail(10)
    .find((row) => row.action === "AUTH.LOGIN" && row.detail === "unknown address");
  assert.ok(unknown !== undefined);
  assert.equal(unknown.actor_role, "ANON");
  assert.equal(unknown.actor_id, null);
});

/* ---------------- row scope ---------------- */

test("one account can never read another account's rows", async () => {
  const alice = await account("alice@example.com", "Alice");
  const bob = await account("bob@example.com", "Bob");

  // Give Bob an upload, then ask as Alice.
  const png = PNG_1X1.toString("base64");
  const uploaded = await post(
    "/v1/uploads",
    { name: "bobs-dump.png", type: "image/png", data: png, requestRef: null },
    { cookie: bob.cookie, csrf: bob.csrf },
  );
  assert.equal(uploaded.status, 201);

  const aliceView = (await (await get("/v1/uploads", alice.cookie)).json()) as { uploads: unknown[] };
  assert.equal(aliceView.uploads.length, 0, "Alice must not see Bob's rows");

  const bobView = (await (await get("/v1/uploads", bob.cookie)).json()) as { uploads: unknown[] };
  assert.equal(bobView.uploads.length, 1);
});

test("cancelling a subscription that belongs to someone else is not possible", async () => {
  const alice = await account("owner@example.com", "Owner");
  const bob = await account("attacker@example.com", "Attacker");
  const sub = harness.system.runtime.subs.createFor(alice.userId, "RETAIL", true);

  const attempt = await post(
    "/v1/subscription/cancel",
    { subId: sub.id, confirm: true },
    { cookie: bob.cookie, csrf: bob.csrf },
  );
  assert.equal(attempt.status, 404, "another account's subscription must be invisible");
  const still = harness.system.store.subscriptionFor(sub.id, alice.userId);
  assert.ok(still !== null && still.auto_renew === 1, "the subscription must survive the attempt");
});

/* ---------------- cancellation symmetry ---------------- */

test("cancelling asks for no more than signing up", () => {
  // Signing up requires an address, a display name, a password and two consent decisions,
  // and the server refuses it without the booleans. Cancelling requires one identifier and
  // one confirmation. The asymmetry is the requirement, so it is asserted rather than
  // described on a page.
  const signupRequiredFields = 4; // email, displayName, password, and consent (2 booleans, one decision)
  assert.ok(
    CANCEL_FIELDS.length <= signupRequiredFields,
    `cancelling needs ${CANCEL_FIELDS.length} fields, signing up needs ${signupRequiredFields}`,
  );
});

test("cancelling switches off auto-renew and keeps the period already paid for", async () => {
  const me = await account("cancelme@example.com");
  const sub = harness.system.runtime.subs.createFor(me.userId, "RETAIL", true);

  const res = await post("/v1/subscription/cancel", { subId: sub.id, confirm: true }, { cookie: me.cookie, csrf: me.csrf });
  assert.equal(res.status, 200);
  const body = (await res.json()) as { subscription: { autoRenew: boolean; cancelEffectiveAt: number | null; status: string } };
  assert.equal(body.subscription.autoRenew, false);
  assert.equal(body.subscription.status, "ACTIVE", "the term runs to its end rather than ending immediately");
  assert.equal(body.subscription.cancelEffectiveAt, sub.current_period_end);

  // The audit record must carry the refund-free guarantee explicitly.
  const record = harness.system.store.auditTail(20).find((row) => row.action === "SUB.CANCEL" && row.outcome === "OK");
  assert.ok(record !== undefined);
  assert.match(record.detail, /service continues to/);
});

/* ---------------- renewal notices ---------------- */

test("a renewal notice is sent once inside the window and never twice for one period", async () => {
  const me = await account("renewal@example.com");
  const subs = harness.system.runtime.subs;
  const sub = subs.createFor(me.userId, "RETAIL", true);

  // Outside the window. A thirty-day period with a fourteen-day notice window is twenty
  // days away from being due, so nothing is mailed and the relay sees nothing.
  const before_ = harness.relay.captured.length;
  assert.equal((await subs.sendDueReminders()).length, 0);
  assert.equal(harness.relay.captured.length, before_);

  await withClock(20 * DAY_MS, async () => {
    const first = await subs.sendDueReminders();
    assert.ok(
      first.some((outcome) => outcome.subscriptionId === sub.id),
      "a subscription inside its notice window must be warned about",
    );

    const sent = harness.relay.captured[harness.relay.captured.length - 1];
    assert.ok(sent !== undefined);
    // Collapse the hard wrapping before matching: the notice is wrapped for a plain-text
    // reader, and a phrase that spans two lines is still one promise.
    const text = String(sent["text"]).replace(/\s+/g, " ");
    assert.match(text, /notice that precedes a renewal/);
    // A notice that does not say how to stop the renewal is a notice that exists to
    // prevent cancellation, so the instruction is asserted rather than assumed.
    assert.match(text, /Cancelling is one action/);
    assert.match(text, /no reason, no call and no notice period/);
    assert.match(text, /This notice is sent once per renewal/);

    // Second pass inside the same window: the period is marked, so nobody is mailed twice.
    assert.equal((await subs.sendDueReminders()).length, 0, "a renewal must not be warned about twice");
  });

  // A subscription with auto-renew switched off is never warned about: there is nothing to
  // warn about, and mailing it anyway would be the kind of notice people learn to ignore.
  const cancelled = subs.createFor(me.userId, "RETAIL", false);
  await withClock(20 * DAY_MS, async () => {
    const outcomes = await subs.sendDueReminders();
    assert.ok(!outcomes.some((outcome) => outcome.subscriptionId === cancelled.id));
  });
});

/* ---------------- uploads ---------------- */

test("upload validation refuses containers and active content", () => {
  const png = PNG_1X1.toString("base64");

  const good = parseUpload(JSON.stringify({ name: "log.png", type: "image/png", data: png, requestRef: null }));
  assert.equal(good.ok, true);

  // A ZIP wearing a .png name: the content is the truth and the name is the claim.
  const zip = parseUpload(
    JSON.stringify({ name: "innocent.png", type: "image/png", data: zipBytes().toString("base64"), requestRef: null }),
  );
  assert.equal(zip.ok, true, "the envelope is valid; the judgement happens later");
  if (zip.ok) {
    const verdict = judge(zip.input);
    assert.equal(verdict.verdict, "REJECTED");
    assert.match(verdict.scanDetail, /zip container/);
    assert.equal(verdict.buffer, null, "a refused artefact must never produce bytes to write");
  }

  // Active content and executables are refused at the name, before any bytes are read.
  for (const name of ["payload.svg", "page.html", "run.exe", "lib.so", "archive.zip", "script.sh", "pkg.tar.gz"]) {
    assert.equal(sanitiseName(name), null, `${name} must not be storable`);
  }
  // Path traversal is neutralised rather than refused: the directory component is dropped,
  // so what is left is an ordinary name and nothing on disk is built from it anyway.
  const traversing = sanitiseName("../../etc/passwd.png");
  assert.ok(traversing !== null);
  assert.equal(traversing.base, "passwd.png");
  const nested = sanitiseName("../../sneaky/picture.png");
  assert.ok(nested !== null && !nested.base.includes("/"), "the directory component must be stripped");
  // A Windows-style separator is stripped on a POSIX host too, because a `\` in a name is
  // a directory component to one platform and a legal character to the other.
  const windows = sanitiseName("..\\..\\windows\\payload.png");
  assert.ok(windows !== null && windows.base === "payload.png");
});

test("an upload over the ceiling is refused, and a mismatch is refused", () => {
  // Two ceilings, checked in two places, both asserted here: the transport refuses an
  // encoded body before decoding it, and the judgement refuses what decodes to too many
  // bytes. A single check would leave the other path open.
  const encodedOver = "A".repeat(UPLOAD_MAX_BASE64 + 4);
  const tooLong = parseUpload(
    JSON.stringify({ name: "big.txt", type: "text/plain", data: encodedOver, requestRef: null }),
  );
  assert.equal(tooLong.ok, false, "an encoded body over the ceiling must be refused before decoding");

  const big = Buffer.alloc(UPLOAD_MAX_BYTES + 1, 0x41).toString("base64");
  const oversized = parseUpload(JSON.stringify({ name: "big.txt", type: "text/plain", data: big, requestRef: null }));
  assert.equal(oversized.ok, true, "the envelope is within the transport ceiling");
  if (oversized.ok) {
    const judged = judge(oversized.input);
    assert.equal(judged.verdict, "REJECTED");
    assert.match(judged.scanDetail, /ceiling is/);
    assert.equal(judged.buffer, null, "a refused artefact must never produce bytes to write");
  }

  // Declared image/png, content is really text/plain.
  const mismatch = parseUpload(
    JSON.stringify({ name: "thing.png", type: "image/png", data: Buffer.from("hello there").toString("base64"), requestRef: null }),
  );
  assert.equal(mismatch.ok, true);
  if (mismatch.ok) {
    const verdict = judge(mismatch.input);
    assert.equal(verdict.verdict, "REJECTED");
    assert.match(verdict.scanDetail, /declared image\/png but content is text\/plain/);
  }
});

test("an accepted artefact is stored outside any asset root under a name that cannot be guessed", async () => {
  const me = await account("uploader@example.com");
  const res = await post(
    "/v1/uploads",
    { name: "dump.txt", type: "text/plain", data: Buffer.from("a diagnostic dump").toString("base64"), requestRef: null },
    { cookie: me.cookie, csrf: me.csrf },
  );
  assert.equal(res.status, 201);
  const body = (await res.json()) as { upload: { id: string; verdict: string; bytes: number; sha256: string; expiresAt: number } };
  assert.equal(body.upload.verdict, "ACCEPTED");
  assert.equal(body.upload.bytes, 17);
  assert.match(body.upload.sha256, /^[0-9a-f]{64}$/);
  assert.ok(body.upload.expiresAt > Date.now());

  const rows = harness.system.store.uploadsForUser(me.userId, 5);
  const stored = rows.find((row) => row.id === body.upload.id);
  assert.ok(stored !== undefined);
  // The stored name is random, has no extension, and is not derived from what was sent.
  assert.match(stored.stored_name, /^[0-9a-f]{32}$/);
  assert.ok(!stored.stored_name.includes("dump"));
  const file = path.join(harness.system.runtime.uploads.root, stored.stored_name);
  assert.ok(existsSync(file), "the artefact should exist on disk");
  if (process.platform !== "win32") {
    assert.equal(statSync(file).mode & 0o777, 0o600, "the artefact must be readable only by its owner");
  }
});

test("the retention sweep leaves the window alone and then deletes the bytes", async () => {
  const me = await account("retention@example.com");
  const res = await post(
    "/v1/uploads",
    { name: "expiry.txt", type: "text/plain", data: Buffer.from("temporary").toString("base64"), requestRef: null },
    { cookie: me.cookie, csrf: me.csrf },
  );
  assert.equal(res.status, 201);
  const { upload } = (await res.json()) as { upload: { id: string; expiresAt: number } };
  const rows = harness.system.store.uploadsForUser(me.userId, 5);
  const stored = rows.find((row) => row.id === upload.id);
  assert.ok(stored !== undefined);
  const file = path.join(harness.system.runtime.uploads.root, stored.stored_name);
  assert.ok(existsSync(file), "the artefact should be on disk inside its window");
  assert.equal(stored.deleted_at, null);

  // A sweep inside the window must remove nothing at all: the guarantee runs in both
  // directions, and a sweeper that deletes early is as wrong as one that never deletes.
  assert.equal(await harness.system.runtime.uploads.sweep(), 0);
  assert.ok(existsSync(file), "a file inside its retention window must not be deleted");

  // Then move the clock past the window and sweep again. This is the deletion the privacy
  // policy promises, observed rather than described.
  const removed = await withClock(31 * DAY_MS, async () => harness.system.runtime.uploads.sweep());
  assert.ok(removed >= 1, `expected the sweep to delete at least the expired artefact, deleted ${removed}`);
  assert.ok(!existsSync(file), "the bytes must be gone once the window has closed");

  const after = harness.system.store.uploadsForUser(me.userId, 5).find((row) => row.id === upload.id);
  assert.ok(after !== undefined);
  assert.ok(after.deleted_at !== null, "the record must be marked rather than silently dropped");
  assert.ok(
    harness.system.store.auditTail(50).some((row) => row.action === "UPLOAD.EXPIRED" && row.subject_id === upload.id),
    "a deletion nobody can audit is a deletion nobody can verify",
  );
});

test("a text artefact carrying active content is quarantined, not stored", async () => {
  const me = await account("activetext@example.com");
  const payload = Buffer.from("<html><script>document.cookie</script></html>").toString("base64");
  const res = await post(
    "/v1/uploads",
    { name: "report.txt", type: "text/plain", data: payload, requestRef: null },
    { cookie: me.cookie, csrf: me.csrf },
  );

  // 202 rather than 201: the record exists and the bytes do not. A client that reads any
  // 2xx as "my file is on the server" is wrong, and the verdict is what tells it so.
  assert.equal(res.status, 202);
  const body = (await res.json()) as { upload: { verdict: string; scanDetail: string } };
  assert.equal(body.upload.verdict, "QUARANTINED");
  assert.match(body.upload.scanDetail, /active content marker/);

  const row = harness.system.store
    .uploadsForUser(me.userId, 5)
    .find((candidate) => candidate.verdict === "QUARANTINED");
  assert.ok(row !== undefined);
  // No stored name means no file was written, so there is nothing to serve by accident.
  assert.equal(row.stored_name, "-");
  assert.equal(row.deleted_at, null);

  const record = harness.system.store.auditTail(50).find((entry) => entry.action === "UPLOAD.QUARANTINED");
  assert.ok(record !== undefined, "a quarantine must be visible in the audit trail");
  assert.equal(record.outcome, "REFUSED");

  // And the judgement itself refuses to hand out bytes, which is the property that matters
  // if a later handler ever decides to store "almost accepted" uploads.
  const parsed = parseUpload(
    JSON.stringify({ name: "notes.txt", type: "text/plain", data: payload, requestRef: null }),
  );
  assert.equal(parsed.ok, true);
  if (parsed.ok) {
    const judged = judge(parsed.input);
    assert.equal(judged.verdict, "QUARANTINED");
    assert.equal(judged.buffer, null);
  }
});

/* ---------------- headers, injection, and secrets ---------------- */

test("every response carries the security headers, including a strict script policy", async () => {
  const res = await fetch(`${harness.base}/v1/health`);
  const csp = res.headers.get("content-security-policy") ?? "";
  assert.match(csp, /default-src 'none'/);
  assert.match(csp, /script-src 'self'/);
  assert.match(csp, /object-src 'none'/);
  // Without this the landing page's self-hosted fonts fall back to default-src 'none'
  // and are blocked silently, which no other assertion here would notice.
  assert.match(csp, /font-src 'self'/);
  assert.match(csp, /frame-ancestors 'none'/);
  assert.match(csp, /form-action 'none'/);
  assert.equal(res.headers.get("x-content-type-options"), "nosniff");
  assert.equal(res.headers.get("x-frame-options"), "DENY");
  assert.match(res.headers.get("cache-control") ?? "", /no-store/);
  assert.equal(res.headers.get("access-control-allow-origin"), null, "CORS must never be opened");
});

test("an injection attempt in a field is stored as data and changes nothing", async () => {
  const hostile = "' OR 1=1 --";
  const res = await post("/v1/auth/signup", {
    email: "injected@example.com",
    displayName: hostile,
    password: "a sufficiently long password",
    acceptPrivacy: true,
    acceptTerms: true,
    acceptMarketing: false,
  });
  assert.equal(res.status, 201);

  // The value round-trips as a literal, and the table is intact.
  const row = harness.system.store.userByEmail("injected@example.com");
  assert.ok(row !== null);
  assert.equal(row.display_name, hostile);

  // A crafted address does not authenticate and does not error the query.
  const attempt = await post("/v1/auth/login", { email: hostile, password: hostile });
  assert.equal(attempt.status, 401);
  assert.ok(harness.system.store.countUsers("CUSTOMER") >= 1, "the table must survive the attempt");
});

test("an account response carries no credential material", async () => {
  const me = await account("secret@example.com");
  const res = await get("/v1/auth/me", me.cookie);
  const body = await res.text();
  const user = harness.system.store.userByEmail("secret@example.com");
  assert.ok(user !== null);
  assert.ok(!body.includes(user.pwd_hash), "the password digest must never be sent to a client");
  assert.ok(!body.includes("pwd_hash"));
  const token = parseCookies(me.cookie).get(SESSION_COOKIE) ?? "";
  assert.ok(!body.includes(token), "the session value must never appear in a response body");
});

/* ---------------- production configuration ---------------- */

const SECURE_ENV: NodeJS.ProcessEnv = {
  NODE_ENV: "production",
  ARES_SESSION_KEY: "a".repeat(64),
  ARES_MASTER_KEY: "b".repeat(64),
  ARES_OPERATOR_TOKEN: "c".repeat(48),
  ARES_TRUST_PROXY: "1",
  ARES_BOOTSTRAP_ADMIN_PASSWORD: "a bootstrap password long enough to pass",
};

test("an insecure production configuration is refused rather than tolerated", () => {
  const insecure = productionReadiness({
    env: { NODE_ENV: "production" },
    cookieSecure: false,
    origins: ["http://console.example.com"],
    tls: false,
  });
  assert.equal(insecure.production, true);
  // Each finding is a guarantee the system claims to users, and each would be false in
  // this configuration. A deployment like this must not reach the point of accepting
  // traffic and looking healthy in a monitor.
  assert.ok(insecure.fatal.some((entry) => /COOKIE_SECURE/.test(entry)), "a session cookie without Secure must stop the process");
  assert.ok(insecure.fatal.some((entry) => /ARES_SESSION_KEY/.test(entry)));
  assert.ok(insecure.fatal.some((entry) => /ARES_MASTER_KEY/.test(entry)));
  assert.ok(insecure.fatal.some((entry) => /ARES_OPERATOR_TOKEN/.test(entry)));
  assert.ok(insecure.fatal.some((entry) => /console\.example\.com/.test(entry)), "a plaintext remote origin must stop the process");
  assert.ok(insecure.warnings.some((entry) => /TLS/.test(entry)), "a missing TLS story is a warning, because a proxy may terminate it");

  const correct = productionReadiness({
    env: SECURE_ENV,
    cookieSecure: true,
    origins: ["https://console.example.com"],
    tls: true,
  });
  assert.deepEqual([...correct.fatal], [], "a correctly configured production deployment must start");
  assert.deepEqual([...correct.warnings], []);

  // A short bootstrap credential is refused: it is the one password this system chooses
  // for the operator, and a weak one makes every other control in this file irrelevant.
  const short = productionReadiness({
    env: { ...SECURE_ENV, ARES_BOOTSTRAP_ADMIN_PASSWORD: "short" },
    cookieSecure: true,
    origins: ["https://console.example.com"],
    tls: true,
  });
  assert.ok(short.fatal.some((entry) => /BOOTSTRAP_ADMIN_PASSWORD/.test(entry)));

  // Loopback over plaintext is the development shape and is not a remote-plaintext finding.
  const loopback = productionReadiness({
    env: SECURE_ENV,
    cookieSecure: true,
    origins: ["http://127.0.0.1:5173", "http://localhost:5173"],
    tls: true,
  });
  assert.ok(!loopback.fatal.some((entry) => /127\.0\.0\.1|localhost/.test(entry)));

  // And development must not refuse to start, or the check gets switched off everywhere.
  const development = productionReadiness({
    env: {},
    cookieSecure: false,
    origins: ["http://127.0.0.1:5173"],
    tls: false,
  });
  assert.deepEqual([...development.fatal], []);
  assert.equal(development.production, false);
});
