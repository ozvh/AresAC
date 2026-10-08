# ZEUS — arbiter + operator console

A server-side anti-cheat adjudication engine, a marketing front that says what it does, and a
monochrome console that observes it. The front is `/`; the console is `/console`.

```
  reporting rings                arbiter (authoritative)                  observer
  ───────────────                ───────────────────────                  ────────
  KMOD  kernel driver  ──┐
  UMON  user-mode      ──┼──► POST /v1/ingest ──► transport ──► schema ──► MAC ──► provenance
  SRV   external       ──┘     (HMAC-signed)        │                                     │
                                                    │                        velocity ──► sequence ──► clock
                                                    │                                     │
                                                    ▼                                     ▼
                                          conviction state machine                 GET /v1/stream
                                          (severity, corroboration,               (SSE, replay,
                                           dwell, ladder, decay)                   drop-to-reset)
                                                    │                                     │
                                                    ▼                                     ▼
                                          hash-chained ledger                     operator console
                                          (durable, tamper-evident)               (read-only by default)
                                                    ▲
                                                    │
                                          POST /v1/control  (operator token + same-origin)
```

The console is a **zero-trust observer**. It never originates telemetry and holds no
scoring table, so nothing it can do — or be tricked into doing — can move a verdict.

## Run it

```bash
npm install
npm run dev:all        # arbiter on 127.0.0.1:8787 + console on 127.0.0.1:5173
```

The arbiter prints an **operator token** at boot. The console is read-only until that
token is entered in the control plane; every mutation is refused without it. Both
processes bind loopback only.

Other entry points:

```bash
npm run arbiter                 # arbiter alone
npm test                        # schema, MAC, replay, doctrine, HTTP, accounts, security
npm run typecheck               # strict tsc, zero errors
npm run build && npm start      # production: arbiter serves the built console on one origin
npm run load                    # measured ingest throughput and latency
npm run demo:unity              # Unity demo: real arbiter + three demo rings on loopback
npm run security                # dependency audit; fails on a high or critical advisory
npm run security:secrets        # source scan for committed credentials and secrets in log calls
```

The deployed checklist — TLS termination, cookie flags, the CORS stance, retention, the
audit log, database permissions, and what a payment-processor integration would have to
add — lives in [docs/SECURITY.md](docs/SECURITY.md).

## Secrets

Secrets are stored in **Infisical**, not on disk. A working copy has no `.env` after the
migration: the values live in the project's Development, Staging and Production
environments and reach the process through `infisical run`. The arbiter does not know the
difference — it still reads `process.env`, so no application code changed. `.env.example`
is now the key *set* — the names the arbiter reads — and stays placeholder-only.

**Local development.** Install the CLI, sign in, and link the directory once:

```bash
brew install infisical/get-cli/infisical   # Windows/Linux: see the CLI install page
infisical login                            # WSL 2, Codespaces, SSH without a browser: infisical login -i
infisical init                             # writes .infisical.json; links this directory
npm run dev:all                            # already wrapped: infisical run --env=dev -- ...
```

`infisical init` writes `.infisical.json`, which holds the local project link only — it
contains no secrets and is safe to commit. `dev`, `dev:all` and `arbiter` in `package.json`
are wrapped, so the team runs the wrapped command by default.

Importing the existing values is a one-time step: on the project's Secrets Overview page,
drag and drop a `.env` file (or use Paste Secrets), review the discovered keys, choose the
target environments, and upload. Nothing is written back to disk.

**Production, CI/CD and Kubernetes.** Do not log in interactively there. Create a machine
identity and authenticate with Universal Auth, then take the client ID and client secret
from the platform's own secret store — the CI secret store, a Kubernetes Secret, the
orchestrator's injection — never from a file in this repository, and never from the
browser. Scope the identity to this project and the environments it needs and nothing
wider:

```bash
INFISICAL_CLIENT_ID=... INFISICAL_CLIENT_SECRET=... \
  infisical run --env=prod -- npm start
```

`npm run start:prod` is the same production wrap in one script.

**Scanning.** If a `.env` was ever committed, its values are in git history and must be
rotated — deleting the file does not remove them. `infisical scan` looks for credentials
already present in a tree:

```bash
infisical scan
```

## Unity demo

`unity/` is the game side of this system: three C# files that sign telemetry and post it to
the real ingest path, plus a scripted timeline that walks a subject from `CLEAN` to `FLAGGED`.
Nothing there decides anything — it is a reporting ring, and it is demonstration code.

```bash
npm run demo:unity                  # arbiter + stand-in client on 127.0.0.1:8799
npm run demo:unity -- --server-only # arbiter only, for a real Unity client
```

With no Unity editor to hand, the stand-in (the default) plays the identical timeline from
Node, so the console is never empty. Drop `unity/Assets/Zeus` into a Unity project and point it
at the same URL to watch the same verdict arrive from a game client.

**The demo is provisioned by a published recipe, not by a transferred credential.** The
production system has no external enrolment exchange — an agent key is derived from
`ZEUS_MASTER_KEY` and a counter, and only the arbiter process holds it — so the demo arbiter
pins the master to the SHA-256 of a published passphrase and both sides derive the same three
identities (`tools/demo-agents.ts` and `unity/Assets/Zeus/Scripts/ZeusWire.cs`). Anything
derived from a published string is published, which is why this binds loopback only and why a
real build needs the per-agent enrolment exchange the limitations above already name.
`tests/unity-demo.test.ts` pins the recipe to the arbiter's own `AgentRegistry.enroll()` and
drives the wire path end to end: an accepted batch, a refused forgery, and a conviction.

The C# itself is **not compiled here** — this environment has no Unity editor and no .NET SDK,
so `npm run typecheck` and `npm test` do not cover it. What is verified is the recipe those
files implement. `unity/README.md` states that plainly rather than implying otherwise.

## The landing page

`/` is the marketing front, restored from the build that was deployed at
`https://01a116fb-32fc-7213-ad7e-40bee4cf26a5.arena.site/`. That deployment was one
self-contained HTML file and its source is not in this repository, so the page was
reconstructed from the deployed artefact itself: its rendered markup section by section, its
icon geometry, its palette and keyframes, and its two typefaces. What that means concretely:

- **The markup is the original's.** `src/landing/` carries the same elements with the same
  Tailwind classes and the same copy, transcribed from the deployed page's DOM rather than
  rewritten to look similar. `src/landing/icons.tsx` is generated from the icons that page
  rendered, so every mark is the same shape at the same per-placement stroke width.
- **The typefaces are served from this origin.** Space Grotesk and JetBrains Mono arrive as
  fifteen `.woff2` files in `public/fonts/`, declared in `src/fonts.css`. The original fetched
  them from Google Fonts; `/privacy` states that these pages load exactly one origin, so the
  files were taken from that build and are now served locally. That is also why `font-src
  'self'` is now explicit in the CSP — without the directive the faces fall back to
  `default-src 'none'`, are blocked, and the page silently renders in whatever the system
  picked. A missing directive looks exactly like a satisfied one.
- **Two cascade-layer mechanics keep this page from touching the console.** `src/index.css`
  scopes four tokens to `.landing` (its panel blue, its hairline, its two families) and hands
  the console's unlayered `*`, `button` and `a` rules back to the utilities layer with
  `revert-layer`. The console keeps every value it shipped with — including its element
  padding and its link colours — while the landing gets the values its own build resolved to.
  Nothing is forked and no utility is renamed.
- **What moves is real, and it is motion the console forbids.** The lightning canvas, the
  marquee, the scanline, the film grain and the block reveals are all present. The reveals are
  a thirty-line `IntersectionObserver` rather than the original's motion library — no
  dependency was added for a fade — and they honour `prefers-reduced-motion` by not happening
  at all.

**Measured against the deployed page, not eyeballed.** At 1440x900, with both pages scrolled
end to end so every reveal has fired, every section's position and height matches the
original: hero `y=232`, architecture `y=958 h=1364`, detection `y=2322 h=1364`, adjudication
`y=3686 h=2065`, collateral-zero `y=5751 h=1721`, footer `h=1523`. Every computed style
sampled — family, size, weight, line-height, letter-spacing, colour, border colour, clip path,
animation name — matches, and the counts of icons (74), canvases, images and sections are
identical. Two differences were expected and left alone: a 1px page width from scrollbar
rendering, and the terminal feed's own ±17px, which is its log window sliding past a two-line
message — the original does the same thing, measuring 1355 and 1372 at different moments.

## The public surfaces

One bundle, no router library: the path selects the surface before anything mounts, so a
stranger opening the policy page never starts the telemetry stream the console boots.

| Path | Surface | What it is |
|---|---|---|
| `/` | `src/pages/Landing.tsx` | the marketing front — what the architecture is, and what it refuses to do |
| `/console` | `src/App.tsx` | the operator console — read-only observer, boots the SSE stream |
| `/request` | `src/pages/BuildRequest.tsx` | ask for a build; the only unauthenticated surface that causes an outbound side effect |
| `/signup` | `src/pages/Signup.tsx` | creates a customer account; two required consents, marketing off by default |
| `/login` | `src/pages/Login.tsx` | one form for customers and administrators |
| `/account` | `src/pages/Account.tsx` | your own consents, subscription, artefacts and password |
| `/admin` | `src/pages/Admin.tsx` | the administrator view: accounts, the audit tail, and account changes |
| `/privacy` | `src/pages/Privacy.tsx` | the policy, written from the code that implements it |

A trailing slash is stripped, and an unrecognised path resolves to the landing page rather
than to a 404 page — the front page is the surface a stranger is meant to meet. `/admin` is in that switch
with no client-side gate, on purpose: the page is a view, not an authority, and it renders
the refusal the server sent it. Nothing in the bundle decides who is an administrator.

API route groups, all of them JSON-only and same-origin:

| Group | Routes |
|---|---|
| telemetry and console | `/v1/ingest`, `/v1/stream`, `/v1/snapshot`, `/v1/subject/<tag>`, `/v1/control`, `/v1/health` |
| build requests | `POST /v1/request` |
| accounts | `POST /v1/auth/signup`, `/login`, `/logout`, `/password`, `GET /v1/auth/me` |
| subscriptions | `POST /v1/subscription/cancel`, `POST /v1/subscription/autorenew` |
| artefacts | `GET /v1/uploads`, `POST /v1/uploads` |
| administration | `GET /v1/admin/summary`, `/users`, `/audit`, `POST /v1/admin/user` |

Dispatch is keyed by `METHOD path`, so a route cannot be reached with the wrong verb: a
path this module owns with a verb it does not accept answers 405 before the origin check
even runs. That is the difference between a rule and a habit.

## Build requests

`/request` asks the operator for a build. The recipient is **not** in the payload: it comes
from the relay's own configuration, because a contact form that lets the caller name the
destination is an open mail relay with extra steps.

The transport speaks one shape — a JSON POST to a send endpoint with a bearer key — which
covers Resend and several other providers. That makes the relay a configuration rather than
a vendor dependency, and keeps an SDK out of a process whose dependency surface is part of
its threat model.

| Variable | Meaning |
|---|---|
| `RESEND_API_KEY` | bearer credential; **absent means spool-only operation** |
| `ZEUS_REQUEST_TO` | the fixed recipient |
| `ZEUS_REQUEST_FROM` | sender; a verified domain is required to send from anything but the provider default |
| `ZEUS_REQUEST_ENDPOINT` | relay endpoint |
| `ZEUS_REQUEST_SPOOL` | spool file for mail that could not be handed to the relay |

**A request is never lost to a configuration error.** With no key, on a 4xx answer, or when
the relay is unreachable, the message is appended to the spool file — created 0600, never
read back into a response — and the outcome is recorded as `SPOOLED` rather than `FAILED`.
Someone asking for a build cannot know the relay was misconfigured, and silently dropping
their request is the one outcome this component refuses. There is one retry, and only for a
condition that can clear on its own: a 5xx or an unreachable host. A 4xx is a decision, and
retrying it only doubles the latency of an answer that has already been made.

Four fences bound the amplification, all of them server-side, because the fence the client
sees is the client's to remove:

- **Closed key set, bounded fields.** Body ceiling 8 KiB; callsign 2–80 characters, address
  ≤ 254, organisation ≤ 120, note 8–2000, and the channel must be one of `RETAIL`,
  `DEVELOPMENT`, `SOURCE` or `EVALUATION`. Every field except the free-text note is refused
  if it contains any control character, because every other field can reach a mail header.
- **Two velocity buckets, and both must clear.** 2 submissions/min per source (burst 2)
  *and* 20/min process-wide (burst 20). Per-source alone is defeated by a spray across
  addresses; process-wide alone lets one caller starve everybody else.
- **A honeypot and a minimum form age.** The dwell value is client-supplied and therefore
  advisory: it filters scripted submissions that never rendered a page, and no decision that
  matters depends on it.
- **Dedupe.** A repeat from one source for one address inside ten minutes answers with the
  original reference instead of mailing the operator twice, and the map is capped so a spray
  cannot grow it.

Header values are single-lined before transmission. `reply_to` is derived from something a
stranger typed, and a relay that accepts a CRLF in an address field is a relay that can be
made to send mail somewhere else.

**Only an accepted request is sealed.** Traps and refusals are counted but never written to
the ledger, because an anonymous caller must not be able to push genuine verdict records out
of a bounded tail. The sealed record carries the relay's verdict, the channel, the reference
and a one-way digest of the address — never the address itself, and never the note.

## Accounts and authority

Two roles, `CUSTOMER` and `ADMIN`; three statuses, `ACTIVE`, `SUSPENDED` and `CLOSED`. A new
account is a customer. The role is not a field any request can set, an administrator exists
only because an existing one granted the role, and the bootstrap account exists only because
it was created from the environment — flagged `must_change_password`, so every privileged
action is refused until that temporary credential is replaced.

**Sessions are server-side records.** The browser holds an opaque random string in a
`zeus_session` cookie; everything about the session — the owner, the role, the expiry,
whether it is revoked — lives in the database. Nothing about authority is encoded in the
value the client holds, so there is nothing in it to forge. That is what "no local auth
token" means concretely: no bearer token in browser storage, no client-side JWT whose claims
the server has to trust, and no flag in the page that says whether someone is an
administrator. The database stores only a digest of the session secret, so a leaked backup of
the sessions table grants no ability to present a session.

| Property | Setting |
|---|---|
| cookie | `zeus_session`, `HttpOnly`, `SameSite=Strict`, `Path=/`, no `Domain` |
| `Secure` | added when `ZEUS_COOKIE_SECURE=1` — required in production, wrong on local HTTP |
| lifetime | 7 days absolute, last-seen refreshed no more than once every 15 minutes |
| CSRF | a synchroniser token, `x-zeus-csrf`, issued by `GET /v1/auth/me` and required on every mutation |
| password | scrypt (N=16384, r=8, p=1), per-account salt, 12–200 characters, timing-safe comparison |
| lockout | 8 failed sign-ins lock the account for 15 minutes |

CSRF uses a synchroniser token rather than a double-submit cookie: only the digest of a
second random value is stored, and the raw value is handed to the page by `GET /v1/auth/me`.
A cross-site request can carry the cookie but cannot read the token, so it cannot complete
the mutation. `SameSite=Strict` and the same-origin check are the other two layers, and
neither of them makes this one redundant.

**Every failure is the same failure.** An unknown address, a wrong password, a suspended
account and a locked one all return one indistinguishable rejection, and the
unknown-address path burns the same hashing work as the real one, so the response time does
not answer the question the response body refuses to. For the same reason a duplicate
sign-up is refused in the same words as any other failure: "already registered" is an
oracle. The audit log records which it was, because the operator needs to know and the
caller must not.

`GET /v1/admin/*` re-derives the caller's role from the session record on every request and
audits the refusal as `AUTHZ.REFUSED`. Two lockout guards are enforced in the handler rather
than merely hidden in the page: an administrator cannot change their own role or status, and
the last administrator cannot be demoted or suspended. Suspending an account ends its
sessions in the same transaction as the status change.

Sign-up and sign-in are rate-limited per source (12/min, burst 6) and sign-up additionally
process-wide (6/min, burst 3), so a spray cannot mint accounts; uploads are limited per
account (10/min, burst 5).

## Plans, artefacts and the privacy page

| Plan | Period | Amount per period |
|---|---|---|
| `EVALUATION` | 30 days | no charge |
| `RETAIL` | 30 days | 1900 minor units |
| `SOURCE` | 90 days | 4900 minor units |

**No payment processor is wired up.** There is no provider credential in this repository, and
inventing one would be worse than not having it. What exists is the authority model a
processor would drive: plans with period lengths, an auto-renew flag, a cancellation state,
and an audit record for every transition. [docs/SECURITY.md](docs/SECURITY.md) names what a
real integration must add — webhook signature verification against the provider's key,
idempotency keys on every mutation, and reconciliation between their state and ours.

**Cancelling costs no more than signing up.** Sign-up takes an address, a display name, a
password and two consent decisions, and the server refuses it without them. Cancelling takes
one identifier and one explicit confirmation — no reason field, no call, no notice period,
no step that exists to slow it down. The test suite asserts that inequality against the
sign-up contract rather than trusting the copy on the page. Cancellation takes effect at the
end of the period already paid for, so nothing is confiscated, and the audit record says so
in as many words.

**A renewal notice precedes every renewal, exactly once per period.** The row stores the
period end that was last warned about, which makes the guarantee "once per renewal" rather
than "recently". The window is `ZEUS_RENEWAL_NOTICE_DAYS` (14 by default); the message is
plain text with no tracking pixel and no rewritten link, and it states the plan, the date,
the amount, and how to stop it.

**Uploads.** There is no multipart parser. Artefacts arrive as base64 inside the same
closed-key JSON envelope as everything else, under a 256 KiB ceiling: multipart parsing has a
long history of parser-differential bugs, and the disagreement between the parser and the
consumer is the exploit. The cost of not having one is a third more bytes on the wire. Name,
content and placement are each checked — the extension must be on a short allowlist of inert
formats, the leading bytes must not be a container or an executable *whatever the name says*,
a declared type that disagrees with the content is refused, and a refusal never produces
bytes to write. Accepted files are stored outside every served directory under a fresh random
name with no extension, mode 0600, and no route serves them back. Every verdict, including a
refusal, is recorded. Files are deleted `ZEUS_UPLOAD_RETENTION_DAYS` (30 by default) days
after upload by a sweeper that removes the file first and marks the row second.

**The policy page.** `/privacy` describes this deployment rather than a template: what is
collected and what deliberately is not, the retention window for each kind of record, the one
third party (the mail relay, and only when a credential has been configured), the AI
assistance used alongside the human work on this system, and the commitments that carry no
qualifier — no testimonials, because none were collected; no pre-ticked marketing box; no
dark patterns. The version string on that page is the version recorded in a consent row at
sign-up, and the retention figures are the configured values, so changing either setting
means changing the page.

## Doctrine

Suspicion is the severity of the **most severe unexpired sample** in the retention
window, decayed while idle. It is deliberately not an average: an averaging score lets
benign noise issued *before* a hard proof dilute it, so a mapped unsigned image would
score lower than the proof it actually is. Nothing an attacker does — flooding benign
traffic first, for instance — can lower the peak.

| # | Invariant | Where it is enforced | Test that fails if it breaks |
|---|---|---|---|
| 1 | Capability is denied before the account is touched | `machine.ts` containment ladder | *containment precedes conviction* |
| 2 | Two independent rings convict; one may not | `machine.ts` corroboration mask | *two rings convict…* / *single ring never convicts* |
| 3 | A single structural proof at severity ≥ 90 convicts alone (`X1`, `X2`, `X3`) | `catalog.ts` `STRUCTURAL_CERTAINTY_SEV` | *a structural proof convicts from a single ring* |
| 4 | Corpus hits (`X6`) and foreign-thread origin (`X5`) at 85–88 do **not** convict alone | same threshold, deliberately at 90 | *a corpus hit alone is strong but not sufficient* |
| 5 | Behavioural evidence from any single ring can never convict, however high it scores | `canConvict` requires corroboration or structural proof | *the external arbiter's own model alone never convicts* |
| 6 | Conviction is sticky; only an operator release clears it | `#recompute` never downgrades `FLAGGED` | *a conviction survives an hour of decay* |
| 7 | Stale evidence cannot corroborate fresh evidence | `#expire` on the sweep | *stale evidence cannot corroborate fresh evidence* |
| 8 | A forged ring or misfiled evidence code is refused | `catalog.ts` `srcMask` + provisioned role | *a forged ring claim is refused* |
| 9 | A larger batch buys no extra rate budget | `Limiter.take(..., cost)` | *a batch is charged for every sample it carries* |
| 10 | Memory is bounded at every level | sample cap, subject cap, latency ring, event ring | *the subject table stays bounded under a hostile id spray* |

Codes `X1`/`X2`/`X3` are proofs of tampering and are the only codes above the
single-ring certainty line. `X5`, `XC` and `X6` sit below it on purpose — each is
strong but individually circumstantial.

## Why each defence exists

- **Closed key set.** An event carrying any key the schema does not model is rejected
  outright, so no unmodelled field can ride along into the scoring path.
- **Per-agent MAC.** Each reporting ring is a distinct principal with its own derived
  key, so a compromised user-mode sentinel cannot present itself as the kernel driver.
  A batch spanning two principals cannot be covered by one MAC and is refused.
- **Provenance, not assertion.** A sample declares its ring, but the declaration is only
  believed after it matches the agent's provisioned role *and* the evidence code's
  authorised source mask. Both failures are counted separately as `ROLE`.
- **Ordering is the arbiter's.** Sender clocks are bounded by a skew window and never
  used for ordering; strictly monotonic per-agent sequences make a captured frame
  useless and a counter reset indistinguishable from an attack.
- **Velocity.** A continuous-refill token bucket per agent, charged for every sample a
  batch carries, so a flood cannot buy adjudication slots.
- **Nothing is stored.** Every response is `no-store`; no CORS headers are ever emitted;
  a browser origin that is not explicitly configured is refused, which closes CSRF and
  cross-site stream theft at once.
- **The console cannot lie usefully.** Severity, classification and authorised ring per
  code exist only server-side.

## Measured, not claimed

`npm run load` drives the real HTTP surface (socket, schema, MAC, replay, provenance,
limiter, state machine) and reports what happened. On the development machine
(Windows, Node v24.21, single process, loopback):

| Phase | Offered | Admitted | Refused | Request p95 | Adjudication p95 |
|---|---|---|---|---|---|
| PROBE — 24 principals pushed past budget | 23,973 evt/s | 4,605 evt/s | 80.79% at the token bucket (`rl 1817`) | 14.00 ms | 20 µs/sample |
| LOAD — 300 principals | 23,967 evt/s | **23,967 evt/s** | **0.00%** | 13.82 ms | 12 µs/sample |
| LOAD — 900 principals, 96 in flight | 89,837 evt/s | **89,837 evt/s** | **0.00%** | 57.44 ms | 5 µs/sample |

539,648 authenticated events were admitted over 6 seconds with zero schema, MAC,
replay or provenance failures, and the ledger chain verified afterwards. The per-agent
rate cap means aggregate throughput scales with the size of the reporting fleet
(120 samples/s per authenticated agent); the PROBE phase is what happens when a small
fleet tries to exceed its own budget.

The 57 ms p95 at the highest concurrency is client-side queueing with 96 requests in
flight, not server service time — the arbiter's own per-sample cost is 5 µs.

Console cost: the event ring holds 60,000 events, the DOM holds ~40 rows, and frames are
coalesced into **one React commit per display frame** regardless of event rate. A
continuous 90k evt/s firehose therefore costs the same render work per frame as a quiet
system. Observed worst case in the browser under the CAPACITY profile: ~1,000 DOM nodes.

## Verification status

- `npm test` — **148/148 passing**, covering schema rejection, MAC forgery, replay,
  clock skew, the token bucket, all ten doctrine invariants, the hash-chained ledger
  (including tamper detection), frame decoders, the live HTTP surface end to end
  (202/401/403/409/413/415/429/400 paths, SSE framing and resume, operator token and
  throttle), the build-request relay, and the account surface: password digests and
  policy, the engine refusing a rewritten audit log, foreign keys and CHECK constraints,
  consent gating, cookie flags, synchroniser-token refusal, origin refusal, uniform
  authentication failures, lockout, session revocation on password change and on
  suspension, row scope for uploads and subscriptions, cancellation symmetry, the
  once-per-period renewal notice, upload judgement (containers, mismatch, quarantine,
  retention), the security headers, injection-as-data, the production-configuration refusal,
  and the Unity demo's recipe lock and wire path.
- `npm run security` — **0 vulnerabilities**, and `npm run security:secrets` —
  **0 findings across 70 files**.
- `npm run typecheck` — zero errors under `strict`, `noUncheckedIndexedAccess`,
  `exactOptionalPropertyTypes` and `verbatimModuleSyntax`.
- Production build served by the arbiter's own static handler and confirmed rendering in
  a browser: 9 panels, live stream, zero console errors, zero failed requests,
  `Content-Security-Policy` intact and no inline script.
- The landing page was checked the same way — through the arbiter, on the production path
  with the strict CSP in force — with both self-hosted faces loading (`document.fonts.check`
  true for each), both images resolving, every section matching the deployed page's geometry
  and computed styles as described above, and zero console errors or CSP violations.

### Known limitations

- **Auth is a local operator token.** The control plane requires a bearer token but the
  read surfaces (`/v1/snapshot`, `/v1/stream`) are protected only by same-origin policy
  and loopback binding. A production deployment must front the console with its
  authenticated session layer. Customer and administrator accounts with server-side
  sessions now exist for the `/signup`, `/login`, `/account` and `/admin` surfaces; the
  console's own read surfaces are still loopback-and-same-origin only.
- **Agent enrolment is in-process.** Keys are derived from a master secret and a counter,
  so the enrolled fleet is only stable while `ZEUS_MASTER_KEY` and enrolment order are
  stable. Real agents need a per-agent enrolment exchange. The Unity demo works around this
  for loopback only, with a published recipe — see the Unity demo section.
- **The fleet is a simulator.** It trades through the real ingest path, but it lives in
  the arbiter process, so it proves the pipeline rather than a distributed deployment.
- **Decay is sweep-driven.** Decay is time-proportional, but only advances when the
  500 ms sweeper runs. A process paused for a long interval will resume with suspicion
  computed for the elapsed wall clock in a single step.
- **The ledger outlives the process; the subject table does not.** Every sealed decision
  is written to the append-only `ledger_records` table, and the chain is re-verified and
  resumed at boot — so a restart continues the chain instead of starting a new one, and a
  record rewritten between runs is named as broken. Live suspicion state (the subject table
  and the telemetry windows) is still memory-resident, so a restart clears that and only the
  irreversible decisions survive. The chain is not yet replicated off-host or streamed to an
  external auditor.

## Layout

```
shared/protocol.ts     wire contract, limits, defensive frame decoders
server/catalog.ts      server-only severity, classification, ring provenance
server/agents.ts       per-agent key derivation, constant-time MAC verification
server/validate.ts     the one boundary where hostile bytes become structured data
server/limiter.ts      token bucket, monotonic sequence, skew window, latency window
server/machine.ts      the conviction state machine (doctrine lives here)
server/ledger.ts       hash-chained decision ledger: durable append-only store, verified on boot
server/sse.ts          broadcaster: replay ring, drop-to-reset backpressure
server/http.ts         transport, security headers, same-origin enforcement
server/http-kit.ts     shared transport primitives and the hardened security headers
server/bootstrap.ts    the one composition root: store, auth, mail, uploads, subscriptions
server/db.ts           sqlite schema, constraints, append-only audit triggers, row-scoped reads
server/passwords.ts    scrypt hashing, policy, timing-safe verification, absent-account work
server/auth.ts         server-side sessions, cookies, synchroniser CSRF, roles
server/routes-auth.ts  account, subscription, upload and administration routes
server/subscriptions.ts plans, symmetric cancellation, once-per-period renewal notices
server/uploads.ts      base64 intake, magic-byte judgement, retention sweeper
server/mailer.ts       relay-shaped mail transport with a spool fallback
server/requests.ts     build-request intake: closed keys, two velocity buckets, honeypot
server/fleet.ts        server-side load generator that uses the real ingest path
server/runtime.ts      composition root, snapshot tick, telemetry windows
src/lib/store.ts       rAF-coalesced telemetry store and bounded event ring
src/lib/account.ts     account client: session and CSRF token held in memory only
src/pages/*            the landing page, signup, login, account, administration, privacy, request form
src/landing/*          the landing's nine sections, generated icon set, reveals, backdrop, canvas
src/fonts.css          @font-face for the two self-hosted families (public/fonts/*.woff2)
public/fonts/*.woff2   Space Grotesk and JetBrains Mono, served from this origin
public/images/*.jpg    the storm plate and the Zeus bust, taken from the original build
src/components/*       ten console panels (see CONSOLE.md for the panel conventions)
tests/*                schema, doctrine, decoder and end-to-end HTTP suites
tools/load.ts          measured throughput/latency harness
tools/dev.ts           runs arbiter + console together
tools/secrets.ts       source scan for credentials and secrets reaching a log call
tools/demo-agents.ts   the demo enrolment recipe, shared by the server, the test and the C#
tools/unity-demo.ts    loopback demo arbiter: pinned demo master, three enrolled rings
unity/Assets/Zeus/     Unity demo client: wire core, transport, scripted scenario
unity/README.md        what the demo does, how to run it, and what is not verified
tests/unity-demo.test.ts  recipe lock plus the ingest path end to end
docs/SECURITY.md       deployed checklist: TLS, cookies, CORS, retention, audit, payments
```
