# ZEUS — Unity demo client

A **demo**. Not the release build, not a shipping integration.

This folder is the game side of the arbiter in this repository: three C# files that sign
telemetry and post it to the real ingest path, plus a scripted timeline that moves a subject
from `CLEAN` to `FLAGGED` so you can watch the conviction happen on the operator console.

The anti-cheat itself is the arbiter in the parent directory. Nothing here decides anything —
it is a reporting ring, and the doctrine it exercises is that a client's claims are only
believed after the server matches them to a provisioned role.

## Drop it in

Copy `Assets/Zeus` into your Unity project's `Assets/` folder. Three files, no packages, no
`manifest.json` changes:

| File | What it is |
|---|---|
| `Scripts/ZeusWire.cs` | The wire core: canonical string, HMAC, JSON framing, agent derivation. **No `UnityEngine` reference** — plain C# so the bytes can be read and diffed without an editor. |
| `Scripts/ZeusIngestClient.cs` | The Unity transport: `UnityWebRequest` POST to `/v1/ingest`. The only file that imports `UnityEngine`. |
| `Scripts/ZeusDemoAgent.cs` | A `MonoBehaviour` that plays the demo timeline. |

## Run it

Terminal, in this repository:

```bash
npm run demo:unity                  # arbiter + stand-in client on 127.0.0.1:8799
npm run demo:unity -- --server-only # arbiter only, for the real Unity client
```

Unity, in a new empty scene:

1. Create an empty GameObject and add the `ZeusDemoAgent` component.
2. Leave `Base Url` at `http://127.0.0.1:8799` unless you passed `--port`.
3. Press **Play**.

Leave `Auto Run` on for the scripted timeline, or turn it off and call `RunTimeline()`
yourself. `SendForgedRingClaim()` is wired to a public method and demonstrates the provenance
check: it declares a kernel-only proof on the user-mode ring, and the arbiter answers `403`
without adjudicating anything. That refusal is the point — a fully compromised client can
fabricate codes, and it still cannot fabricate the ring they are believed on.

Open the operator console (`npm run build` first, then the arbiter serves it at the same URL)
to watch the verdict and the ladder step change.

The console is at `http://127.0.0.1:8799/console`; `/` is the website landing page.
Use `--server-only` when running Unity: the Node stand-in uses the same agent identities
and would otherwise compete for their sequence counters. Restart the demo server before
starting a fresh Unity Play session, which resets the client's sequence counters to zero.

## What you should see

| Phase | Code | Ring | Expected |
|---|---|---|---|
| `CLEAN` | `XD` | UMON | stays `CLEAN` — an allowlist hit is benign |
| `BEHAVIOURAL` | `X8` | SRV | reaches `PENDING` at most — behavioural evidence from one ring never convicts |
| `STRUCTURAL` | `X2` | KMOD | `FLAGGED` after the dwell window, and capability is contained before the account is touched |

The third phase is the one that matters: a single structural proof at severity ≥ 90 is the only
thing that convicts from one ring, and it is required to be *sustained* (1.2 s of dwell), not
merely touched once.

## How the client is provisioned without any credential being transferred

The production system has no external enrolment exchange: an agent key is derived from
`ZEUS_MASTER_KEY` and a counter, and only the arbiter process holds it. A game on another
machine therefore cannot be provisioned — that gap is listed as a known limitation in the root
`README.md`, and closing it properly needs a per-agent enrolment exchange that does not exist
yet.

For the demo, both sides compute the same identity from a **published** recipe
(`tools/demo-agents.ts`):

```
master   = SHA256("zeus-unity-demo/loopback-only-not-a-production-secret")   32 bytes
agent id = hex(HMAC_SHA256(master, "agent-id:<role>:<counter>"))[0..16]
agent key= HMAC_SHA256(master, "agent-key:<id>")                            32 bytes
signature= hex(HMAC_SHA256(key, join("\n", canonical(each event))))
```

`tests/unity-demo.test.ts` asserts that recipe against the arbiter's own
`AgentRegistry.enroll()`, so if the server's derivation ever changes, the C# above is known to
be stale instead of silently producing batches that come back as an indistinguishable `401`.

**This is a demo shortcut, and it is the reason the demo is loopback-only.** Anything derived
from a published string is published; a real build must exchange a per-agent key over a channel
it can authenticate, and must never contain a master key.

## Not verified here

There is no Unity editor and no .NET SDK in this repository's development environment, so these
files are **not compiled by `npm run typecheck`, `npm test` or CI**. What *is* verified is the
recipe they implement: the canonical string, the HMAC, the agent derivation and the full HTTP
path are exercised by `tests/unity-demo.test.ts` and by `npm run demo:unity`, which drives the
same bytes from Node. If you change the wire format, change `tools/demo-agents.ts` too — the
test will tell you when the two have drifted.
