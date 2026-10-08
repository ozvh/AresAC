/**
 * Unity demo suite.
 *
 * The demo ships a C# client that cannot be compiled here (no Unity editor, no .NET SDK), so
 * these tests pin the half that can be checked from this side: that the recipe the C# client
 * implements is byte-for-byte the one the arbiter enforces, and that a client using nothing but
 * that recipe drives the real HTTP ingest path to an accepted batch, a refused forgery, and a
 * conviction.
 *
 * The assertions are written from the client's side of the wire. "The demo works" is not a
 * test; "an agent id derived from the published passphrase is accepted while a ring claim it
 * did not earn is refused" is.
 */
import assert from "node:assert/strict";
import { after, before, test } from "node:test";
import type { AddressInfo } from "node:net";
import {
  LIMITS,
  PROTOCOL_VERSION,
  ROLE_RING,
  canonicalEvent,
  type EvidenceCode,
  type IngestEvent,
  type Role,
} from "../shared/protocol.ts";
import { AgentRegistry, signEvent } from "../server/agents.ts";
import { Fleet } from "../server/fleet.ts";
import { createArbiterServer } from "../server/http.ts";
import { Ledger } from "../server/ledger.ts";
import { Arbiter } from "../server/machine.ts";
import { Broadcaster } from "../server/sse.ts";
import type { Runtime } from "../server/runtime.ts";
import { DEMO_ROLES, demoAgentId, demoAgentKey, demoMaster, demoSign, demoSubject } from "../tools/demo-agents.ts";
import { runDemoTimeline, type DemoPhase } from "../tools/unity-demo.ts";
import { testRuntime } from "./harness.ts";

const SUBJECT = demoSubject("unity-demo-player");
/** The console view identifies a subject by the first 12 hex of its digest (`#subject` in machine.ts). */
const SUBJECT_TAG = SUBJECT.slice(0, 12);
const COUNTER_OF: Readonly<Record<string, number>> = { KMOD: 1, UMON: 2, SRV: 3 };

type Running = { readonly base: string; readonly stop: () => Promise<void> };

/** Boot a real arbiter on a real socket, with the demo agents enrolled as the demo tool does. */
async function spinUp(): Promise<Running> {
  const registry = new AgentRegistry(demoMaster());
  DEMO_ROLES.forEach((role) => registry.enroll(role));

  const ledger = new Ledger();
  const arbiter = new Arbiter(ledger);
  const bus = new Broadcaster(LIMITS.replayRing);
  const fleet = new Fleet(registry, { sessions: 0, tps: 0, origin: "http://127.0.0.1:1", seed: 1 });
  const runtime: Runtime = testRuntime({ arbiter, ledger, bus, registry, fleet, operatorToken: "d".repeat(48) });
  const server = createArbiterServer({ runtime, consoleOrigins: ["http://127.0.0.1:5173"], staticDir: null });
  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
  runtime.start();

  const address = server.address() as AddressInfo;
  return {
    base: `http://127.0.0.1:${address.port}`,
    stop: async (): Promise<void> => {
      runtime.stop();
      await new Promise<void>((resolve) => server.close(() => resolve()));
    },
  };
}

test("the published recipe is the arbiter's own enrolment recipe", () => {
  const registry = new AgentRegistry(demoMaster());
  DEMO_ROLES.forEach((role, index) => {
    const agent = registry.enroll(role);
    assert.equal(
      agent.id,
      demoAgentId(role, index + 1),
      `${role} id must match the recipe the Unity client implements`,
    );
    assert.ok(agent.key.equals(demoAgentKey(agent.id)), `${role} key must match the recipe`);
  });
});

test("the recipe's MAC is the signature the arbiter verifies", () => {
  const id = demoAgentId("KMOD", 1);
  const key = demoAgentKey(id);
  const event: IngestEvent = {
    v: PROTOCOL_VERSION,
    a: id,
    k: SUBJECT,
    s: 1,
    t: 1_700_000_000_000,
    r: ROLE_RING.KMOD,
    c: "X2",
    m: 1,
  };
  const canonical = canonicalEvent(event);
  assert.equal(demoSign(key, canonical), signEvent(key, canonical));
  // The canonical field order is the contract, so it is asserted rather than assumed: a
  // reordered canonical string still produces a valid-looking digest and would fail only as a
  // 401 at the far end.
  assert.equal(canonical, `1|${id}|1|1700000000000|0|X2|1|${SUBJECT}`);
});

/* ------------------------------------------------------------------ */
/*  The wire, over a real socket                                       */
/* ------------------------------------------------------------------ */

let running: Running;
const seqByRole = new Map<Role, number>();

async function postAs(
  role: Role,
  code: EvidenceCode,
  options: { ring?: number; sig?: string | null; subject?: string } = {},
): Promise<Response> {
  const id = demoAgentId(role, COUNTER_OF[role] ?? 1);
  const key = demoAgentKey(id);
  const next = (seqByRole.get(role) ?? 0) + 1;
  seqByRole.set(role, next);

  const event: IngestEvent = {
    v: PROTOCOL_VERSION,
    a: id,
    k: options.subject ?? SUBJECT,
    s: next,
    t: Date.now(),
    r: (options.ring ?? ROLE_RING[role]) as IngestEvent["r"],
    c: code,
    m: 1,
  };
  const headers: Record<string, string> = { "content-type": "application/json" };
  const sig = options.sig === undefined ? demoSign(key, canonicalEvent(event)) : options.sig;
  if (sig !== null) headers["x-zeus-sig"] = sig;

  return fetch(`${running.base}/v1/ingest`, {
    method: "POST",
    headers,
    body: JSON.stringify([event]),
  });
}

before(async () => {
  running = await spinUp();
  for (const role of DEMO_ROLES) seqByRole.set(role, 0);
});

after(async () => {
  await running.stop();
});

test("a batch signed with the recipe alone is accepted", async () => {
  const response = await postAs("UMON", "XD");
  assert.equal(response.status, 202);
  const body = (await response.json()) as { ok: boolean; n: number };
  assert.equal(body.ok, true);
  assert.equal(body.n, 1);
});

test("an unsigned batch is refused as unauthenticated", async () => {
  const response = await postAs("UMON", "XD", { sig: null });
  assert.equal(response.status, 401);
  assert.equal(((await response.json()) as { e: string }).e, "SIG");
});

test("a forged ring claim is refused before anything is adjudicated", async () => {
  // The KMOD agent, presenting a kernel-only proof on the user-mode ring. This is the lie the
  // demo's SendForgedRingClaim() sends, and it must not reach the scoring path.
  const response = await postAs("KMOD", "X2", { ring: ROLE_RING.UMON });
  assert.equal(response.status, 403);
  assert.equal(((await response.json()) as { e: string }).e, "ROLE");
});

test("an evidence code the ring is not authorised to report is refused", async () => {
  // X4 is a user-mode behavioural code; a kernel agent reporting it is refused even though the
  // declared ring is its own, because authority is the code's, not the sender's to choose.
  const response = await postAs("KMOD", "X4");
  assert.equal(response.status, 403);
  assert.equal(((await response.json()) as { e: string }).e, "ROLE");
});

test("a sustained structural proof convicts the demo subject", async () => {
  const deadline = Date.now() + 8_000;
  let verdict = "CLEAN";
  while (Date.now() < deadline) {
    const accepted = await postAs("KMOD", "X2");
    assert.equal(accepted.status, 202);
    const snapshot = (await (await fetch(`${running.base}/v1/snapshot`)).json()) as {
      subjects: ReadonlyArray<{ su: string; vd: string; st: string; ct: boolean }>;
    };
    const found = snapshot.subjects.find((entry) => entry.su === SUBJECT_TAG);
    if (found !== undefined) verdict = found.vd;
    if (verdict === "FLAGGED") {
      // Containment precedes conviction: capability is denied before the account is touched.
      assert.equal(found?.ct, true, "a convicted subject's capability must be contained");
      break;
    }
    await new Promise((resolve) => setTimeout(resolve, 120));
  }
  assert.equal(verdict, "FLAGGED", "X2 at severity 95 sustained past the dwell window must convict");
});

test("the demo timeline the tool plays emits only accepted samples", async () => {
  // Its own arbiter, because runDemoTimeline starts every sequence counter at 1 and the shared
  // server above has already spent those counters — a replay refusal would look like a
  // timeline bug rather than the isolation mistake it would be.
  const solo = await spinUp();
  try {
    const phases: DemoPhase[] = [
      { label: "CLEAN", role: "UMON", code: "XD", seconds: 1 },
      { label: "BEHAVIOURAL", role: "SRV", code: "X8", seconds: 1 },
    ];
    const outcome = await runDemoTimeline(solo.base, {
      subject: demoSubject("timeline-probe"),
      perSecond: 8,
      log: (): void => undefined,
      phases,
    });
    assert.equal(outcome.refused, 0, "no scripted sample may be refused");
    assert.ok(outcome.accepted >= 8, `expected most of the script to land, got ${outcome.accepted}`);
  } finally {
    await solo.stop();
  }
});
