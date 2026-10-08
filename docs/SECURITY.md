# Security

This document is the security record for the ZEUS arbiter: what is implemented, where it
lives, and what is still missing. It is written to be read top to bottom by whoever
deploys this, and every claim in it names the file that makes the claim true. Where a
control is not implemented, that is stated under its own heading rather than softened into
a sentence.

---

## 1. Trust model

The server is authoritative. The client is not a participant in any decision — it is a
renderer.

- **Authority is re-derived on every request from a database row.** See
  `server/routes-auth.ts`: `authorise()` loads the session record, then the account row,
  and compares the role held against the role required. No request body, header or cookie
  can name a role, an owner, or a price.
- **Sessions are server-side records, not tokens.** `server/auth.ts` explains the shape:
  the browser holds an opaque random string in an `HttpOnly` cookie, and every fact about
  the session — owner, role, expiry, revocation — lives in the `sessions` table. There is
  nothing in the client's value to forge.
- **Only digests are stored.** The `sessions` table holds `token_hash` — HMAC-SHA256 under
  a domain-separated key (`server/auth.ts`, `digest()`) — and `csrf_hash`, which is a digest
  of the synchroniser token kept as tamper evidence, so an edited row fails closed rather
  than accepting the edit. A leaked backup of the sessions table cannot present a session,
  and the password digests are scrypt (`server/passwords.ts`). The plaintext password is
  never stored, never logged, and never returned.
- **The client holds no credential that outlives the tab.** The CSRF token lives in a
  module-level variable in `src/lib/account.ts`, and the session lives in an `HttpOnly`
  cookie no script can read.
- **Nothing on the client is evidence.** `src/pages/Admin.tsx` may hide controls, but
  `GET /v1/admin/*` refuses a customer regardless of what any page rendered.

---

## 2. The control list, item by item

Each entry states what is implemented, where, and the residual risk or production duty.

### 1. Secrets out of source control

Secrets are read from the environment only. There is no secret literal in `server/`,
`shared/`, `tools/` or `src/`. `server/bootstrap.ts` resolves the session key, telemetry
master key, operator token and mail relay configuration in one place; the bootstrap
administrator credential is read by `ensureBootstrapAdmin()` from `server/index.ts`; and
`server/mailer.ts` builds its endpoint from `ZEUS_REQUEST_ENDPOINT`.

Residual: an operator can still paste a real key into `.env.example`. That file is
tracked, and review must treat any non-placeholder value in it as a leak.

### 2. Environment variables

`docs/SECURITY.md` §3 is the table. Every variable is read through
`process.env` in `server/bootstrap.ts` or `server/index.ts`; `.env.example` documents the
intended set and contains only placeholders. Values themselves are delivered by
**Infisical**: the project's Development, Staging and Production environments hold them,
and `infisical run` injects them into the process — `dev`, `dev:all` and `arbiter` in
`package.json` are already wrapped, so no application code changed. There is no `.env` on
disk. See §23 for the non-local path and the Secrets section in `README.md`.

### 3. Keys not committed

`.gitignore` excludes `.env`, `*.pem`, `*.key`, `*.crt`, `.zeus-data/`, `*.db*`,
`.zeus-*.log`, `*.log`, `.zeus-requests.log`, `uploads/`, `quarantine/`, `dist/` and
`node_modules/`. `npm run security:secrets` (`tools/secrets.ts`) fails the build if a
tracked file contains a secret-shaped literal, a private key block, or an `.env` file that
is not the template.

Residual: `.gitignore` protects against accident, not against a deliberate `git add -f`;
the scanner is the second layer and must be run in CI.

### 4. Admin route protection

Four guards, in order, on every account route (`server/routes-auth.ts`, `handleAccountRoutes`):

1. **Same origin** — `preflight()`, via `originAllowed()` in `server/http-kit.ts`.
2. **Session** — `auth.resolve()`, a database lookup by token digest.
3. **CSRF** — `auth.verifyCsrf()`, synchroniser token, on mutations only.
4. **Role** — `authorise({ role: "ADMIN" })`, and an account carrying
   `must_change_password` is refused every privileged action until it changes it.

Dispatch is keyed by `"METHOD path"` (`ROUTES` in `server/routes-auth.ts`), and a path in
`OWNED` reached with the wrong verb answers 405 before the origin check — so probing the
admin surface cannot distinguish an existing route from a missing one by status code.
Authority is never hidden behind a client-side condition.

A refusal is audited: `authorise()` writes `AUTHZ.REFUSED` with
`required ADMIN, held CUSTOMER at <path>`.

Residual: there is no second factor on the admin surface. An administrator's stolen
password plus a stolen session cookie is sufficient until the account is suspended.

### 5. Authentication

`server/auth.ts`. Signup and login are the only unauthenticated write paths
(`POST /v1/auth/signup`, `POST /v1/auth/login`). Failures are uniform: unknown address,
wrong password, suspended account and locked account all answer `401` with the single
message `those credentials are not valid`, and the unknown-address path burns the same
scrypt work through `verifyAbsent()` (`server/passwords.ts`). What the failure actually
was goes to the audit log, where only the operator reads it.

Lockout: `MAX_FAILURES = 8` within `LOCK_MS = 15 minutes`, time-bounded rather than
permanent so an attacker cannot lock an account out forever by guessing badly.

Residual: no second factor and no email-verification loop. An address is trusted as typed
(`EMAIL_SHAPE` in `server/auth.ts`). A signup for an address that is already registered
answers `409` with the same generic message used for every other signup refusal — it never
confirms that an account exists and never echoes the address — but the status code itself
does disclose that the address is in use. See the email-verification row in §10.

### 6. Authorisation and user permissions

Two roles, `CUSTOMER` and `ADMIN`, declared as a database `CHECK` constraint, not only as a
TypeScript union (`server/db.ts`). Every mutating route re-derives the role from the row.
Administrators cannot change their own role or status (403), and the last remaining
administrator cannot be demoted or suspended (409) — both enforced in
`server/routes-auth.ts`, both covered by `tests/security.test.ts`.

Residual: two roles, no finer permission model. Anything an administrator can reach, every
administrator can reach.

### 7. Input sanitisation

Every public write path parses to a **closed key set**: extra fields are refused, not
ignored (`server/validate.ts`, `server/requests.ts` `parseBuildRequest`, `server/uploads.ts`
`parseUpload`, `server/subscriptions.ts` `parseCancel`, `server/routes-auth.ts`
`parseSignup`/`parseLogin`/`parsePassword`/`parseAdminAction`). Identifiers are
shape-checked, not merely typed: a subscription id must match `^[0-9a-f]{32}$`, a request
reference `^[0-9a-f]{8}$`, a user id `^[0-9a-f]{32}$`. Control characters are refused in
upload names and single-line fields; the build-request note is the one field that permits
`\n`, through an explicit `CONTROL_MULTILINE` check in `server/requests.ts`.

### 8. XSS

Three layers:

- **The Content-Security-Policy in `server/http-kit.ts`** (`SECURITY_HEADERS`) forbids
  inline script, forbids every third-party origin, and sets `object-src 'none'` and
  `base-uri 'none'`. There is no inline `<script>` anywhere in the app, and no CDN.
- **React escapes by default.** No `dangerouslySetInnerHTML` appears anywhere in `src/`.
- **Uploads cannot be rendered.** `.svg` and `.html` are not on the allowlist
  (`server/uploads.ts`), the stored name has no extension, and no route serves stored bytes
  back — the absence of a read route is the control.

Residual: `style-src 'self' 'unsafe-inline'` is required by the styling pipeline. It permits
style injection, not script execution, and no user-supplied value reaches a style attribute.

### 9. SQL injection

There is no dynamically assembled SQL. Every statement in `server/db.ts` is a string
literal and every value travels as a `?` bind; no template literal appears inside
`#stmt(` or `.prepare(`. `tests/security.test.ts` asserts that by reading the source, and
separately round-trips `' OR 1=1 --` through signup and login to prove the value is stored
as data.

Residual: the single exception is `PRAGMA user_version = ${SCHEMA_VERSION}` in
`server/db.ts` `#migrate()`, which cannot take a bind parameter. It is safe because
`SCHEMA_VERSION` is derived from `MIGRATIONS.length` at compile time and no caller can
influence it. It is documented in the file.

### 10. Database rules and constraints

`server/db.ts` declares the rules in DDL so a handler bug cannot write a row the schema
rejects:

- `CHECK` on `role`, `status`, `kind`, `plan`, `verdict`, `actor_role` and `outcome`;
- `CHECK (email LIKE '%_@_%._%')` and an address length band, so address shape is enforced
  twice — in the handler and in the table;
- `CREATE UNIQUE INDEX users_email_unique ON users (email COLLATE NOCASE)`, so case cannot
  defeat uniqueness;
- `CHECK (expires_at > created_at)` and `CHECK (length(sha256) = 64)`;
- `REFERENCES users (id) ON DELETE CASCADE`, enforced only because
  `PRAGMA foreign_keys = ON` is set explicitly — SQLite disables it by default;
- `PRAGMA trusted_schema = OFF`, so a value can never name a table or column;
- a migration version guard that **refuses to open a database newer than the build
  understands**.

Verified by `tests/security.test.ts` through a second `DatabaseSync` connection standing in
for anyone else with file access: UPDATE and DELETE on `audit_log` raise, a dangling foreign
key is refused, `SUPERUSER` is refused, and a duplicate address differing only in case is
refused.

### 11. Rate limiting

`server/limiter.ts` is a token bucket, used at every boundary:

| Boundary | Limit | Where |
| --- | --- | --- |
| Signup | 12/min, burst 6 per source, **plus** 6/min, burst 3 process-wide; the process-wide ceiling is the one adjustable limit (`ZEUS_SIGNUP_PER_MIN`), the per-source gate is not | `server/routes-auth.ts` |
| Login | 12/min, burst 6 per source | `server/routes-auth.ts` |
| Upload | 10/min, burst 5 per account | `server/routes-auth.ts` |
| Build request | 2/min, burst 2 per source **and** 20/min, burst 20 process-wide | `shared/protocol.ts` `REQUEST_LIMITS`, charged in `server/requests.ts` |
| Telemetry ingest | `LIMITS.ratePerSec` / `LIMITS.rateBurst` per agent | `server/http.ts` |
| Control plane | one action per `LIMITS.controlMinIntervalMs` | `server/http.ts` |

Bucket keys are charged against `sourceOf()` (`server/http-kit.ts`), which uses the socket
address and consults `x-forwarded-for` **only** when `ZEUS_TRUST_PROXY=1`, and then takes
the **rightmost** entry — the hop the trusted proxy appended. Trusting the leftmost entry
would let a caller choose its own bucket key.

Residual: buckets live in one process's memory. A multi-process deployment needs a shared
store, or the limits multiply by the number of processes.

### 12. CSRF

`server/auth.ts`. A synchroniser token, not a double-submit cookie. The token is
**derived, not stored**: `Auth.csrfFor(rawSessionCookie)` returns
`HMAC(sessionKey, "csrf" + "\u0000" + cookie)`, and `GET /v1/auth/me` returns that value.
It must come back in the `x-zeus-csrf` header on every mutation, where
`verifyCsrf(identity, rawCookie, presented)` recomputes it, first checks the stored
`csrf_hash` as tamper evidence, and then compares in constant time. A cross-site request can
carry the cookie but cannot read this session's response, so it cannot obtain the token.
`SameSite=Strict` and the origin check are two further, independent conditions.

Deriving it fixed a defect worth recording, because the failure landed on the account
holder: a stored token can be handed out only once, so issuing a usable token to a reloaded
page meant invalidating the previous one. Every read of `/me` rotated it, so two tabs of the
account page invalidated each other's token and a mutation racing a poll was refused. A CSRF
defence that fires on the user's own concurrent requests is one people work around. The
derived value is stable for the life of the session, is stored nowhere, and changes when the
session is re-issued — so a change in authority still changes it. There is deliberately no
setter for `csrf_hash` in `server/db.ts`.

### 13. CORS

**No `Access-Control-*` header is emitted anywhere.** The origin check in
`server/http-kit.ts` `originAllowed()` is a request-admission test, not a grant: an allowed
origin is permitted to make the request, and still cannot read the response cross-origin
because the browser receives no permission header. `ZEUS_CONSOLE_ORIGINS` is the exact-match
list of origins permitted to call the API from a browser. A request with no `Origin` header
is allowed through, because a non-browser principal has no ambient credentials to spend —
which is what lets the enrolled agent fleet authenticate by MAC.

Consequence for a browser client: the console must be served from an origin on that list,
or same-origin with the arbiter (`--serve-static=dist`).

### 14. HTTPS

Direct TLS is implemented and optional. `server/index.ts` `resolveTls()` reads
`ZEUS_TLS_CERT` and `ZEUS_TLS_KEY` as PEM file paths, and `createArbiterServer()` in
`server/http.ts` builds an `https.createServer` from that material; the boot banner's
`transport` line states which listener is running.

Both variables must be set together. Setting exactly one, or naming a file that cannot be
read, refuses to start with exit code 3 — the failure mode this avoids is a listener that
looks configured and is not. With both unset the listener is plain HTTP, which is
acceptable only because it binds `127.0.0.1`: either put a proxy in front of it, or
terminate TLS here.

### 15. Security headers

One table, `SECURITY_HEADERS` in `server/http-kit.ts`, applied by `send()` to **every**
response including errors:

```
Content-Security-Policy: default-src 'none'; script-src 'self'; style-src 'self' 'unsafe-inline';
                         img-src 'self' data:; font-src 'self'; connect-src 'self'; base-uri 'none';
                         form-action 'none'; frame-ancestors 'none'; object-src 'none'
Strict-Transport-Security: max-age=31536000; includeSubDomains
X-Content-Type-Options: nosniff
Referrer-Policy: no-referrer
X-Frame-Options: DENY
Cross-Origin-Opener-Policy: same-origin
Cross-Origin-Resource-Policy: same-origin
Permissions-Policy: camera=(), microphone=(), geolocation=(), payment=()
Cache-Control: no-store, no-cache, must-revalidate
```

`form-action 'none'` means a form cannot navigate a submission anywhere, so the only way a
payload leaves the origin is the same-origin `fetch` the pages already make.

### 16. Secure cookies

`serialiseCookie()` in `server/auth.ts` emits `Path=/`, `HttpOnly`, `SameSite=Strict`, and
`Secure` when `ZEUS_COOKIE_SECURE=1`. No `Domain` attribute, so the cookie is first-party
only. The name is deliberately not `__Host-`-prefixed: that prefix demands `Secure`, which
local HTTP cannot set.

**Set `ZEUS_COOKIE_SECURE=1` in production.** The boot banner states which mode is active.

### 17. Debug mode off

**There is no debug mode to disable.** No route, branch or stack trace is gated on
`NODE_ENV`; no error handler returns an exception message to a client — `fail()` emits a
stable `{ e, msg }` pair from a fixed vocabulary, and the only places a raw
`error.message` is written are `server/index.ts` stderr writes, for a bind failure or
unreadable TLS material. `NODE_ENV` is read in exactly one place: `server/prodcheck.ts`
`isProduction()`, which decides whether the readiness checks warn or refuse. It enables no
debugging behaviour in either direction.

Residual: nothing about the runtime's behaviour changes with `NODE_ENV` — the controls are
unconditional, which is why that is acceptable. `NODE_ENV=production` is a safety switch for
*configuration* (§2.18), not for code paths, and the two must not be confused.

### 18. Production settings

`server/index.ts` prints, at boot: the schema version, `foreign_keys` state, the count of
append-only triggers, whether the session cookie is `Secure`, the upload retention window,
the renewal notice window, the relay target, the spool path, whether this listener speaks
TLS, and then one `[!]` line per configuration finding — the readiness warnings from
`server/prodcheck.ts` and the generated-secret notices. A deployment that lost
`ZEUS_SESSION_KEY` still works, and the operator is
told that everyone will be signed out on restart.

**Enforced at boot.** `server/prodcheck.ts` `productionReadiness()` is a pure function of
the environment plus two facts the caller already has — whether the cookie carries `Secure`
and whether the listener speaks TLS — and `server/index.ts` exits **3 before binding the
socket** when it reports a fatal finding. Production is claimed by `NODE_ENV=production`
**or** `ZEUS_ENV=production`, so a platform that rewrites `NODE_ENV` cannot silently demote
a deployment to development and switch the checks off.

Fatal, meaning the process refuses to start:

- the session cookie's `Secure` flag is off;
- `ZEUS_SESSION_KEY` or `ZEUS_MASTER_KEY` is unset or is not 64 hex characters — a generated
  key is printed into the boot banner, where a supervisor's log keeps it;
- `ZEUS_OPERATOR_TOKEN` is unset or shorter than 32 characters;
- a permitted origin in `ZEUS_CONSOLE_ORIGINS` is plaintext and is not loopback;
- `ZEUS_BOOTSTRAP_ADMIN_PASSWORD` is set and shorter than the 12-character policy floor.

Warnings, meaning the risk is real but depends on topology the process cannot see, so it
starts and prints them as `[!]` lines: no TLS material on this listener; `ZEUS_TRUST_PROXY`
is not `1`, so behind a proxy every client collapses into one rate-limit bucket and the
audit trail records the proxy as the source; no bootstrap administrator password, so the
console has no authorised reader; and every permitted origin being plaintext. A production deployment reads its secrets from
Infisical through a machine identity — `infisical run --env=prod -- npm start`, or the
`start:prod` script — so the process's environment is injected at launch rather than read
from a file beside the binary.

`tests/security.test.ts` asserts the fatal set, the absence of false positives on a correct
production configuration, and that a development run is not refused. `.env.example` ships
`NODE_ENV=development` precisely so that a copy of the template is never silently a
production deployment.

### 19. Server-side access only

There is no client-side authorisation. Every account, subscription, upload and admin read
goes through `server/routes-auth.ts` and is decided from the database. `src/lib/account.ts`
holds no state that the server trusts; it is a transport.

### 20. Row-level security

Row scope is a `WHERE` clause in `server/db.ts`, not a convention in a handler:

- `subscriptionFor(id, userId)` — the only accessor for a single subscription takes the
  owner id, so no code path can ask for somebody else's row;
- `uploadsForUser(userId, limit)` — the only per-user upload read takes the owner id;
- `auditForActor(actorId, limit)`, `listConsents(userId)`, `countLiveUploads(userId)`,
  `activeSubscription(userId)`, `dueRenewalNotices(...)` — all scoped.

Cross-account attempts answer 404, not 403, so a caller cannot learn that another account's
row exists. Asserted twice in `tests/security.test.ts`. See §7 for the PostgreSQL
translation.

Residual: SQLite has no roles, so this process necessarily holds write access to its own
file. The enforcement is the query, and the fallback protection is the append-only audit
trigger.

### 21. Password hashing

`server/passwords.ts`. scrypt with `N=16384, r=8, p=1`, a 16-byte salt per password and a
32-byte key, stored as the self-describing digest `scrypt$N$r$p$salt$key`. `maxmem` is
capped at 64 MiB, and `parse()` refuses a digest whose parameters would demand more — so a
tampered row cannot become a memory-exhaustion primitive against the login endpoint.
Verification is `timingSafeEqual`, and a digest that does not parse fails closed instead of
throwing.

Policy: 12–200 characters, not blank, not on a short common list, and it may not contain
the local part of the account's own address. Rejections are counted.

Residual: no breach-corpus check. `server/passwords.ts` says so and names Pwned Passwords
as the production addition.

### 22. No local auth tokens

Nothing about authority is encoded in a value the client holds. There is no JWT, no bearer
token, no client-side admin flag. The session is an opaque random string in an `HttpOnly`
cookie; `src/lib/account.ts` keeps the CSRF token in memory only and deliberately uses no
storage API.

Residual: the **operator token** for the console control plane is entered by the operator
and held in a module-level variable in `src/lib/api.ts` for the life of the page. It is not
the customer session, and it is written to no cookie, no URL, and neither `localStorage` nor
`sessionStorage` — a reload asks for it again, and the console says so where the field is.
It is still a client-held credential while the page is open: an XSS on the console origin
would reach it, so treat the console origin as privileged.

### 23. Server-side secrets

`ZEUS_MASTER_KEY`, `ZEUS_OPERATOR_TOKEN`, `ZEUS_SESSION_KEY`, `ZEUS_BOOTSTRAP_ADMIN_PASSWORD`
and `RESEND_API_KEY` are read from the environment in `server/bootstrap.ts`,
`server/index.ts` and `server/mailer.ts`, and are compared and used only on the server. Their values live in Infisical, not in the
repository: locally `infisical run --env=dev` injects them, and a deployment authenticates a
machine identity with Universal Auth and takes the client ID and client secret from the
platform's own secret store. A credential is never written into a file that travels with
the code.

Because `ZEUS_SESSION_KEY` is domain-separated (`digest()` in `server/auth.ts`), the same
key derives the session digest, the CSRF digest and the address digest without collision —
and callers that only need to key something on an address get `ipDigest()`, not the key.

### 24. `.env` excluded from version control

`.gitignore` lists `.env`, with `.env.example` tracked and placeholder-only. Because secrets
are delivered from Infisical, `.env` is not created at all after the migration; the ignore
rule stays as the second line of defence. `.infisical.json`, which `infisical init` writes,
holds the local project link only — no secrets — and is intentionally committable.

### 25. No secrets in logs

No code path logs a request body, an address, a token or a digest of a password.
`server/index.ts` prints the operator token only when it was **generated** for that process
(the case where the operator has no other way to obtain it) and prints
`from environment (ZEUS_OPERATOR_TOKEN)` when it came from configuration. `server/mailer.ts`
exposes `maskAddress()`, which keeps enough of an address to recognise one you already know
and not enough to harvest one. The audit trail stores `ip_hash`, never the address.

Residual: the boot banner in a log file is a disclosure surface for a generated operator
token. Do not retain or share that log, and set `ZEUS_OPERATOR_TOKEN` in any deployment
whose stdout is collected.

### 26. Parameterised SQL

See §2.9. One statement literal per accessor in `server/db.ts`, values bound, asserted from
source by `tests/security.test.ts`.

### 27. Server-side form validation

Every form's contract is re-checked on the server; the client copy is a courtesy.
`parseSignup` requires exactly the documented keys and `acceptPrivacy === true` before the
account row is written, and `Auth.signup()` audits a refusal when consent is missing
(`server/auth.ts`). An account cannot exist without a recorded consent row.

### 28. Upload validation

See §6.

### 29. Dependency patching

`npm audit --audit-level=high` via `npm run security`. The runtime dependency surface is two
packages (`react`, `react-dom`); everything else is a build-time dev dependency. Adding a
compiled native module is treated as a security decision, not a convenience — which is why
password hashing uses the built-in scrypt rather than Argon2id
(`server/passwords.ts`).

### 30. Security scan

```sh
npm run typecheck          # tsc --noEmit, strict
npm test                   # the full suite, including tests/security.test.ts
npm run security           # npm audit --audit-level=high
npm run security:secrets   # scans tracked source for secret-shaped literals and .env leaks
infisical scan             # Infisical's own scan for credentials already present in the tree
```

`tests/security.test.ts` is written from the attacker's side: it asserts that the database
refuses an UPDATE on the audit log, that an unknown address costs the same work as a known
one, that a customer reaching for an admin route is refused **and leaves a refusal in the
audit trail**, and that one account cannot read another's rows.

### 31. Missing audit logs

Every path that changes authority, money or identity writes an audit record: `AUTH.SIGNUP`,
`AUTH.LOGIN`, `AUTH.LOGOUT`, `AUTH.PASSWORD_CHANGED`, `AUTHZ.REFUSED`, `ADMIN.BOOTSTRAP`,
`ADMIN.ACCOUNT_UPDATED`, `SUB.CANCEL`, `SUB.AUTORENEW`, `SUB.RENEWAL_NOTICE`, `UPLOAD.ACCEPTED`,
`UPLOAD.REJECTED`, `UPLOAD.QUARANTINED` and `UPLOAD.EXPIRED`. `Store.audit()` is the only
writer. A build request
that was actually handed to the relay additionally seals a `REQUEST` record in the decision
ledger — a bounded tail of decisions that matter — and a refused request is counted and
audited but never sealed, so an anonymous caller cannot push genuine verdicts out of it.
See §5.

### 32. Excessive DB permissions

Honest statement: SQLite has no roles, so this process holds write access to its own file
(`server/db.ts` states this rather than claiming otherwise). What is genuinely restricted:
the database lives outside every asset root and outside the web root; `ATTACH` and
`load_extension` are never called; `PRAGMA trusted_schema = OFF` is set; no statement is
dynamic; and the audit log and the decision ledger are immutable by trigger even for this
process (§33).

Residual: the database file's mode is not set by the code. `Store` creates the parent
directory but does not `chmod` the file, so it inherits the process umask. Run the process
under a dedicated account, keep the data directory outside the deployed tree, and confirm
the file is `0600` and owned by that account on the host.

---

### 33. Durable, tamper-evident decision ledger

Every sealed decision is written to `ledger_records` as it is appended, and it is written
**before** the ledger's in-memory head moves, so a failed write cannot leave the head
pointing past what is on disk. The table carries the same UPDATE/DELETE triggers as
`audit_log` (§32), so the record rewrite a corrupted or hostile writer needs is refused by
the engine even for this process.

On boot the ledger re-reads the **whole** stored chain, re-verifies every link from genesis,
and resumes its sequence and head from the last record. That is what makes the chain one
chain across a restart rather than two that agree on nothing (`server/ledger.ts`,
`#recover`). A record that no longer verifies puts recovery into a BROKEN state naming the
first bad sequence; `server/bootstrap.ts` turns that into a boot notice, and the state is
sticky — appending after a break cannot repair it, so a tamper that happened before a
restart is still reported after it. `tests/ledger-persistence.test.ts` asserts all three:
continuation across a restart, detection of a record rewritten between runs, and the
engine refusing an UPDATE or DELETE on the table.

Verification is only meaningful from genesis, which is why the whole chain is read: a window
that starts mid-chain has no predecessor to check its first record against. The ledger holds
decisions, not telemetry, so that set is small next to the event stream.

Residual: runtime verification walks the retained 400-record window plus any break found at
boot, so a record tampered with *while the process is running* and outside that window is
caught at the next restart rather than immediately. The chain is also not replicated: a
`ledger_records` table deleted and rebuilt from genesis verifies cleanly, and detecting that
needs an external anchor — a head digest published somewhere this process does not control —
which is not implemented.

---

## 3. Environment variables

Names come from `.env.example`. Each was confirmed against the code that reads it.

| Variable | Purpose | If unset |
| --- | --- | --- |
| `ZEUS_MASTER_KEY` | 64 hex chars. Derives per-agent telemetry MACs, so the enrolled fleet is stable across restarts. | A fresh key is generated per boot and a `[!]` notice is printed; previously issued agent keys stop verifying. |
| `ZEUS_OPERATOR_TOKEN` | Console control-plane credential, minimum 32 characters. | A 24-byte random token is generated and printed in the boot banner. |
| `ZEUS_CONSOLE_ORIGINS` | Comma-separated exact-match list of browser origins allowed to call the API. | Falls back to the four loopback development origins in `server/index.ts`. |
| `ZEUS_TRUST_PROXY` | `1` makes the rightmost `x-forwarded-for` entry authoritative for rate-limit bucketing. | Buckets are charged on the socket address. Set this **only** behind a proxy you control. |
| `ZEUS_SIGNUP_PER_MIN` | Raises the process-wide signup ceiling (default 6/min, burst 3), for a launch or an automated suite. Bounded, and the per-source signup gate is deliberately not adjustable. | The built-in default. |
| `ZEUS_SESSION_KEY` | 64 hex chars. Signing key for session, CSRF and address digests. | A fresh key per process; every session is invalidated on restart, and a notice is printed. |
| `ZEUS_DB` | SQLite file for accounts, sessions, consents, subscriptions, uploads and the audit log. | `.zeus-data/zeus.db`. |
| `ZEUS_UPLOAD_DIR` | Directory the stored artefacts are written to, created mode `0700`, write mode `0600`. | `.zeus-data/uploads`. |
| `ZEUS_BOOTSTRAP_ADMIN_EMAIL` | Address for the first administrator, created only when no `ADMIN` row exists. | No administrator is created; the boot line says so. |
| `ZEUS_BOOTSTRAP_ADMIN_PASSWORD` | Password for that first administrator; must pass the policy. | Same as above. |
| `ZEUS_COOKIE_SECURE` | `1` adds `Secure` to the session cookie. | `0`: the cookie is sent over plain HTTP. **Must be `1` in production.** |
| `ZEUS_TLS_CERT` | PEM certificate path. With `ZEUS_TLS_KEY` set, this listener speaks HTTPS directly. | Plain HTTP. Setting one without the other, or naming an unreadable file, refuses to start (exit 3). |
| `ZEUS_TLS_KEY` | PEM private key path. | As above. |
| `RESEND_API_KEY` | Mail relay credential. | Mail is appended to the spool and reported `SPOOLED`. A request is never lost for want of a credential. |
| `ZEUS_REQUEST_TO` | Recipient of build requests. Fixed here, never in the payload. | `cagelove094@gmail.com` (`server/mailer.ts` `DEFAULT_RECIPIENT`). |
| `ZEUS_REQUEST_FROM` | Sender header for relayed mail. | `ZEUS Arbiter <onboarding@resend.dev>`. |
| `ZEUS_REQUEST_ENDPOINT` | Relay endpoint. | `https://api.resend.com/emails`. |
| `ZEUS_REQUEST_SPOOL` | Spool file for mail that could not be relayed. | `.zeus-requests.log` in the working directory, written mode `0600`. |
| `ZEUS_UPLOAD_RETENTION_DAYS` | Days an uploaded artefact is kept before the sweeper deletes it. Clamped to 1–365. | `30`. **Also the figure the privacy policy states** (`src/pages/Privacy.tsx`), so changing it means changing the policy copy. |
| `ZEUS_RENEWAL_NOTICE_DAYS` | Days before a renewal that the one-per-period notice is sent. Clamped to 1–90. | `14`. |
| `PORT` | Listen port. | `8787`. |
| `NODE_ENV` | `production` arms the readiness checks in `server/prodcheck.ts` so an insecure configuration stops the process instead of warning. Gates no code path. | Treated as development: the checks warn and the process starts. The template ships `development`. |

Read by the code but absent from the template — add them to `.env.example` if you use them:

| Variable | Read in | Default |
| --- | --- | --- |
| `ZEUS_ENV` | `server/prodcheck.ts` | Unset. `production` here has the same effect as `NODE_ENV=production`. |
| `ZEUS_SESSIONS` | `server/index.ts`, `server/bootstrap.ts` | `6` |
| `ZEUS_TPS` | `server/index.ts`, `server/bootstrap.ts` | `60` via `index.ts`, `0` via `bootstrap()` |
| `ZEUS_SEED` | `server/index.ts`, `server/bootstrap.ts` | `0x5eed` |

**Must be set in production:** `NODE_ENV=production` (or `ZEUS_ENV=production`) to arm the
refusal, `ZEUS_MASTER_KEY`, `ZEUS_SESSION_KEY`, `ZEUS_OPERATOR_TOKEN`,
`ZEUS_COOKIE_SECURE=1`, `ZEUS_CONSOLE_ORIGINS`, `RESEND_API_KEY`, and `ZEUS_TRUST_PROXY`
decided explicitly. Four of those are enforced rather than advised: once production is
claimed, a missing master key, session key or operator token, or a session cookie without
`Secure`, stops the process before it binds its socket. A `ZEUS_BOOTSTRAP_ADMIN_PASSWORD`
that is set must also clear the 12-character floor.

**Generated in development, with a `[!]` notice at boot:** `ZEUS_MASTER_KEY`,
`ZEUS_SESSION_KEY`, `ZEUS_OPERATOR_TOKEN`. The first two make state not survive a restart;
the third is printed for the operator to use.

---

## 4. Production deployment checklist

1. **Decide where TLS terminates.** The process binds `127.0.0.1`, so the usual shape is a
   proxy in front of it — nginx, Caddy or a cloud load balancer — with the process port
   never exposed. A single-host deployment can instead terminate TLS here by setting
   `ZEUS_TLS_CERT` and `ZEUS_TLS_KEY`; the boot banner's `transport` line says which
   listener is running, and an incomplete pair refuses to start.
2. **Set `ZEUS_COOKIE_SECURE=1`** so the session cookie carries `Secure`. Confirm the boot
   banner reads `cookie Secure=ON`.
3. **Decide `ZEUS_TRUST_PROXY` deliberately.** Set `1` only when a proxy you control is
   directly in front of the process; then the rightmost `x-forwarded-for` entry is
   authoritative for rate limiting. Leave `0` when the process is directly reachable, or a
   caller can choose its own bucket key.
4. **Set `ZEUS_CONSOLE_ORIGINS` to the exact production origins.** No wildcard, no
   trailing slash, no scheme mismatch. Remember that no CORS header is ever emitted: a
   browser client must be same-origin with the arbiter or served from an allowed origin that
   loads the console from the same origin it calls.
5. **Serve the console from the same origin** with `--serve-static=dist`, or place it
   behind the same proxy on an origin that is on the list.
6. **Set fixed secrets** for `ZEUS_MASTER_KEY` and `ZEUS_SESSION_KEY` (64 hex characters
   each) so sessions and agent keys survive a restart, and set `ZEUS_OPERATOR_TOKEN` so it
   is not printed into a log.
7. **Create the first administrator once.** Set `ZEUS_BOOTSTRAP_ADMIN_EMAIL` and
   `ZEUS_BOOTSTRAP_ADMIN_PASSWORD`, start the process, sign in, change the password — the
   account is refused every privileged route until you do — then **remove both variables
   from the environment**. Leaving them set keeps a known credential valid.
8. **Own the data directory.** Run the process as a dedicated unprivileged account, keep
   `ZEUS_DB` and `ZEUS_UPLOAD_DIR` outside the deployed tree and outside any asset root,
   confirm the database file is `0600` and owned by that account, and back it up by copying
   the database **and** its `-wal`/`-shm` sidecars while the process is stopped, or with
   `sqlite3 .backup`.
9. **Set the retention window and match the policy.** `ZEUS_UPLOAD_RETENTION_DAYS` must
   equal the number `src/pages/Privacy.tsx` states (30 by default). The sweeper runs every
   60 seconds from `Runtime.housekeep()`.
10. **Set `ZEUS_RENEWAL_NOTICE_DAYS`** to the window in which the once-per-period renewal
    email is sent (14 by default). Every auto-renewing subscription is warned exactly once
    per period, inside this window, and the notice tells the reader how to stop it.
11. **Configure the mail relay** with `RESEND_API_KEY`; verify the spool is empty after a
    test request, and alert on a non-zero spool. `SPOOLED` means a person's request was
    accepted but not delivered.
12. **Back up the audit log with the database.** It cannot be edited or deleted by any
    process, including this one — which means an unbacked-up audit log is unrecoverable.
13. **Run the scans in CI:** `npm run typecheck`, `npm test`, `npm run security`,
    `npm run security:secrets`.
14. **Watch the boot banner.** Every `[!]` line is a configuration finding — the readiness
    warnings and the bootstrap notices share that marker — and the lines that must read as
    expected are the schema version, the foreign-key and append-only-trigger counts, the
    cookie mode, and the `transport` line.
15. **Claim production explicitly.** Set `NODE_ENV=production` (or `ZEUS_ENV=production`)
    so the readiness checks refuse rather than warn, and confirm the process got past them:
    it exits 3 before binding if it did not. A deployment that never claims production is a
    deployment whose insecure configuration is only ever a warning.

---

## 5. The audit log

`audit_log` in `server/db.ts`. It is append-only, enforced by two SQL triggers rather than
by application discipline:

```sql
CREATE TRIGGER audit_log_no_update BEFORE UPDATE ON audit_log
BEGIN SELECT RAISE(ABORT, 'audit_log is append-only'); END;
CREATE TRIGGER audit_log_no_delete BEFORE DELETE ON audit_log
BEGIN SELECT RAISE(ABORT, 'audit_log is append-only'); END;
```

An `UPDATE` that matches no rows fires no trigger, which is why the boot check and the test
count the triggers in `sqlite_master` instead of provoking a write: a verification that
cannot fail is not a verification.

**Recorded:** timestamp, the acting account id and role (`ANON`, `CUSTOMER`, `ADMIN`,
`SYSTEM`), the action, the subject id, the outcome (`OK` or `REFUSED`), a human-readable
detail, and `ip_hash` — an HMAC digest of the source address.

**Deliberately never recorded:** the raw source address, the user-agent string (only its
digest, on the session row), any session token or CSRF token, any password or password
digest, and the free-text body of a build request. A refused request is counted and audited
but never sealed into the ledger, because an anonymous caller must not be able to push
genuine verdict records out of a bounded tail.

**Verify the triggers are present**, at boot or by hand:

```sql
SELECT name FROM sqlite_master
 WHERE type = 'trigger' AND name IN ('audit_log_no_update','audit_log_no_delete');
```

Two rows means the guarantee holds. `Store.invariants()` does exactly this count, and
`server/index.ts` prints it as part of the `audit` line.

---

## 6. Uploads

`server/uploads.ts`. The most important decision in the file is **the absence of a multipart
parser**: uploads arrive as base64 inside the same closed-key JSON envelope as every other
write, so there is no parser to disagree with the consumer about where a field ends.

Accepted types — text/plain (`.txt`, `.log`, `.md`), text/csv, application/json and the
image family (`.png`, `.jpg`, `.jpeg`, `.gif`, `.webp`) and `.pdf`. Everything else is
refused rather than accepted or quarantined: an unlisted format is one whose safety nobody
has reasoned about.

**Refused outright, whatever the name says.** `detect()` reads the leading bytes before
anything else, and container and executable signatures come first:

| Signature | Identified as |
| --- | --- |
| `PK\x03\x04`, `PK\x05\x06` | zip container |
| `\x1f\x8b` | gzip container |
| `7z\xbc\xaf` | 7z container |
| `Rar!` | rar container |
| `\x7fELF` | ELF executable |
| `MZ` | PE executable |
| `\xfe\xed\xfa\xce`, `\xfe\xed\xfa\xcf`, `\xcf\xfa\xed\xfe` | mach-o executable |
| `#!` | shebang script |

A file named `.png` whose bytes are `PK\x03\x04` is a ZIP archive, and the name is the
attacker's claim, not the file's. `.svg` and `.html` are absent from the extension allowlist
because they are active content and would be a stored-XSS vector the moment anything
rendered them. All of this is why **no antivirus engine is claimed**: the dangerous shapes
never reach storage, so there is nothing left for a scanner to find. A deployment that wants
signature scanning should call one, and `UploadVerdict` is where its answer would go.

Also enforced: the declared type must match the detected content (a mismatch is refused),
and unidentified non-text bytes are refused rather than stored on a guess — the UTF-8
decode is strict, so a lone continuation byte is not "text".

**Placement.** Bytes are written under `ZEUS_UPLOAD_DIR` (default `.zeus-data/uploads`),
created mode `0700`, written mode `0600` with the exclusive flag, under a random 32-hex name
with **no extension**. The original name influences nothing on disk. Nothing serves these
bytes back: there is no read route, and the absence of one is the control.

**Quarantine.** All three verdicts are reachable. Text-shaped payloads — `text/*` and
`application/json` — are scanned by `activeContent()` for markers that only make sense in
active content: `<script`, `</script`, `<iframe`, `<object`, `<embed`, `<svg`,
`javascript:`, `<?php`, `<%`, `<!entity`, `document.cookie`, `onerror=` and `onload=`. A hit
returns `QUARANTINED` with a null buffer, so **no bytes are written** (`stored_name` stays
`-`); the row and an audit record with action `UPLOAD.QUARANTINED` and outcome `REFUSED` are
still written, and the route answers `202` rather than `201`. Only text-shaped types are
scanned: searching a PNG for `<script` would be a search of compressed bytes.

Quarantining rather than refusing is deliberate. A cheat log can legitimately contain a
fragment of code, and a silent refusal teaches the user nothing while discarding the signal
the operator wants; storing it would put a `<script>` one refactor away from being served.
So the record is kept and the bytes are not. This is a heuristic, not a signature scanner:
it recognises the shapes that matter for the formats that can still be uploaded, and the
containers that could carry a package are refused outright above.

**Retention.** Every row carries `expires_at`, and `UploadService.sweep()` deletes the file
first and marks the row second, so a failure leaves a row claiming a file exists — visible
and retried — rather than an orphaned file nothing will ever delete. Each deletion is
audited as `UPLOAD.EXPIRED`. The window is the same number the privacy policy states.

Failure direction when storage is unavailable: the row is written before the bytes are, so a
crash between the two leaves a record of an artefact that does not exist, which the sweeper
treats as a successful deletion.

---

## 7. Row-level security, and the PostgreSQL translation

**Today (SQLite).** Row scope is a `WHERE` clause, never a post-hoc check:

- `subscriptionFor(id, userId)` is the only way to read one subscription, and it takes the
  owner id. `Subscriptions.cancel()` therefore cannot act on another account's row even if
  it were called from somewhere new — `server/subscriptions.ts` says this in as many words.
- `uploadsForUser(userId, limit)` is the only per-user upload read.
- `listConsents(userId)`, `activeSubscription(userId)`, `countLiveUploads(userId)`,
  `auditForActor(actorId, limit)` are all scoped the same way.
- No accessor takes a client-supplied owner. A handler that forgot a check cannot pass one.

A cross-account attempt answers **404, not 403**, so a caller cannot learn that another
account's row exists. `tests/security.test.ts` asserts Alice cannot see Bob's upload row and
that cancelling another account's subscription answers 404 and leaves the subscription
running.

**Translation to PostgreSQL.** SQLite has no roles, so the boundary is enforced only by the
query. Postgres can enforce the same rule one layer lower, and should:

```sql
-- The application connects as this role. It cannot bypass policies and does not own the tables.
CREATE ROLE zeus_app LOGIN PASSWORD '...' NOBYPASSRLS NOSUPERUSER;

GRANT SELECT, INSERT, UPDATE, DELETE ON users, sessions, consents, subscriptions, uploads
  TO zeus_app;
-- The audit log is append-only: INSERT and SELECT only, and no UPDATE or DELETE grant.
GRANT SELECT, INSERT ON audit_log TO zeus_app;

ALTER TABLE subscriptions ENABLE ROW LEVEL SECURITY;
ALTER TABLE uploads       ENABLE ROW LEVEL SECURITY;
ALTER TABLE consents      ENABLE ROW LEVEL SECURITY;
ALTER TABLE sessions      ENABLE ROW LEVEL SECURITY;

-- The application sets this per transaction from the session it already resolved:
--   SET LOCAL app.user_id = '<uuid>';
CREATE POLICY subs_own ON subscriptions
  USING (user_id = current_setting('app.user_id'))
  WITH CHECK (user_id = current_setting('app.user_id'));

CREATE POLICY uploads_own ON uploads
  USING (user_id = current_setting('app.user_id'))
  WITH CHECK (user_id = current_setting('app.user_id'));
```

Three rules go with it:

1. **The table owner must not be the application role.** A table's owner bypasses its own
   policies unless `FORCE ROW LEVEL SECURITY` is set; separate credentials are the point.
2. **Set `app.user_id` from the server's resolved session, inside the transaction**, and
   never from a request field. This is the same rule `authorise()` follows today.
3. **Keep the audit log append-only in the database, not just in code.** Replace the SQLite
   triggers with a `BEFORE UPDATE OR DELETE` trigger, and grant the application role no
   `UPDATE`/`DELETE` on the table — belt and braces, because the grant is the one that
   survives a handler bug.

---

## 8. Paid-processor integration requirements

**NOT IMPLEMENTED.** There is no payment processor wired: no provider credential, no
charge, no webhook. `server/subscriptions.ts` states this rather than implying otherwise, and
`PLANS` carries amounts only so the renewal notice can state one (`RETAIL` 1900 minor units
per 30 days, `SOURCE` 4900 per 90 days, `EVALUATION` free).

What exists is the authority model a processor would drive: plans with period lengths, an
`auto_renew` flag, a cancellation state that takes effect at period end, a `reminder_sent_for`
period marker, and an audit record for every transition.

A real integration must add all of the following. None of them is optional:

1. **Verify every webhook's signature** against the provider's signing key, over the raw
   body, with a constant-time comparison and a replay window on the timestamp. An unsigned
   webhook endpoint is an endpoint that grants entitlement to anyone who can POST.
2. **Idempotency keys on every charge and every state transition**, so a retry cannot bill
   twice.
3. **Reconcile against the provider's records on a schedule.** Their state is the truth
   about money; ours is a cache of it. Drift must be detected by a job, not by a customer.
4. **Never trust a client-supplied price, plan name, period length or currency.** The plan
   comes from our table, keyed by an id the client names and nothing more.
5. **Never treat a browser redirect as payment confirmation.** Only a verified webhook is
   evidence, and it must be the trigger for the entitlement.
6. **Handle the failure direction deliberately**: downgrade at period end rather than
   revoking mid-term, and never charge a subscription whose `auto_renew` is `0`.
7. **Keep card data out of this system entirely.** No PAN, no CVC, ever — provider-hosted
   fields or a redirect flow only.

---

## 9. What the product promises, and how engineering is held to it

These are user-facing commitments that constrain the engineering. The policy page is
`src/pages/Privacy.tsx`, served at `/privacy`, and its `VERSION = "2026-10-07"` must match
`PRIVACY_VERSION` in `server/auth.ts` — a consent row cites that exact string, so the two
move together.

1. **Uploads are deleted after the retention window.** The window is
   `ZEUS_UPLOAD_RETENTION_DAYS` (30 by default), the policy page states the same number, the
   sweeper deletes the bytes and marks the row, and each deletion is audited.
2. **Cancelling never takes longer than signing up.** Signing up needs four fields and two
   consent decisions; cancelling needs one identifier and one confirmation
   (`CANCEL_FIELDS` in `server/subscriptions.ts`). This is **asserted, not advertised**:
   `tests/security.test.ts` fails if `CANCEL_FIELDS` grows past the signup contract, and
   separately asserts that cancelling switches off auto-renew, keeps the paid period, and
   leaves `service continues to <date>` in the audit record.
3. **Every auto-renewal is preceded by an email.** `Subscriptions.sendDueReminders()`
   sends once per period inside `ZEUS_RENEWAL_NOTICE_DAYS` of the period end, and the
   `reminder_sent_for` column is what makes it once per period rather than once ever. The
   notice is plain text, states the plan, the date and the amount, and says how to stop it
   in one action. `tests/security.test.ts` asserts the once-per-period property and the text.
   The marker moves only after the relay answers: a duplicate notice is the failure
   direction chosen over a renewal nobody was warned about.
4. **No fabricated testimonials.** The privacy page states that this product shows none,
   and nothing in `src/` renders a quote, a rating or a customer logo. Do not add one.
5. **Consent is real.** Marketing consent is an explicit opt-in, defaults to off, and is
   recorded as a row (`consents`, kind `MARKETING`) with its version. An account cannot be
   created without accepting the privacy policy and terms, and the attempt is audited when
   it is refused.
6. **AI assistance is disclosed.** The privacy page says plainly that AI was used alongside
   the human work on this project. Keep that statement current if the practice changes.

---

## 10. Not implemented

Unmissable, so nothing here is mistaken for a passing sentence.

| Item | State | Detail |
| --- | --- | --- |
| **Payment processor** | **NOT IMPLEMENTED** | No provider, no charge, no webhook. See §8 for the seven requirements a real integration must add. |
| **Second factor for administrators** | **NOT IMPLEMENTED** | An administrator's stolen password plus a stolen session is sufficient until suspension. |
| **Email verification** | **NOT IMPLEMENTED** | An address is trusted as typed. Signup does not send a confirmation, so a typo becomes an account nobody can access. Residual disclosure: a signup for an already-registered address answers `409` with a generic message that confirms nothing and echoes nothing, so the status code alone reveals that the address is in use. Verification by email is what closes it. |
| **Breach-corpus password check** | **NOT IMPLEMENTED** | The policy uses a short common list plus length. `server/passwords.ts` names the Pwned Passwords range API as the production addition. |
| **Signature scanning of uploads** | **NOT IMPLEMENTED, by design** | Containers and executables are refused before storage, and active content in a text payload is quarantined without being stored (§6), so no dangerous artefact is written. What is absent is a signature database: `judge()` is a rule set, not a scanner. |
| **Shared rate-limit state across processes** | **NOT IMPLEMENTED** | `server/limiter.ts` is in-process memory. Multiple processes multiply every limit. |
| **Database file permissions, fully covered** | **PARTIAL** | `Store` creates the parent directory mode 0700 and applies `chmod 0600` to the database file itself, reporting nothing if the platform refuses. The WAL and shared-memory sidecars are created later by SQLite and are not re-moded, and on Windows the call does not implement POSIX modes; a host policy is still the control there. |
| **Audit-log export, retention and tamper evidence beyond the triggers** | **NOT IMPLEMENTED** | The log is append-only and complete, but there is no external sink, no hash chain, and no retention policy. Off-host shipping is the production addition. |

Two further residual risks that are not gaps so much as properties to be aware of:

- **The operator token lives in memory for the life of the console page**
  (`src/lib/api.ts`) and is written to no browser storage. Treat the console origin as
  privileged anyway.
- **The boot banner can print a generated operator token.** Set `ZEUS_OPERATOR_TOKEN` when
  stdout is collected anywhere.
