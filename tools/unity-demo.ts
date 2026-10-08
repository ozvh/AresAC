/**
 * Unity demo arbiter. DEMO ONLY — loopback, a public passphrase, no fleet.
 *
 * Runs the real arbiter (real schema validation, real MAC verification, real replay and
 * provenance checks, real rate limiter, real conviction state machine) on loopback, with
 * exactly three enrolled agents — KMOD, UMON, SRV — whose ids and keys both this process and
 * the Unity client derive from the published recipe in `tools/demo-agents.ts`.
 *
 * The synthetic fleet is switched off, so everything the console shows came from a client:
 * the Unity game, or `--stand-in` (a Node client using the same recipe) when there is no
 * Unity editor to hand.
 *
 *   npm run demo:unity                 # arbiter + stand-in client, console-visible
 *   npm run demo:unity -- --server-only  # arbiter only, for the real Unity client
 *
 * Nothing here changes the server: the demo agents are enrolled through the same
 * `AgentRegistry.enroll()` the fleet uses, and the ingest path is the ordinary one.
 */
import { createHmac } from "node:crypto";
import { existsSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import {
  PROTOCOL_VERSION,
  ROLE_RING,
  canonicalEvent,
  type EvidenceCode,
  type IngestEvent,
  type Role,
} from "../shared/protocol.ts";
import { bootstrap } from "../server/bootstrap.ts";
import { createArbiterServer } from "../server/http.ts";
import { DEMO_PASSPHRASE, DEMO_ROLES, demoAgentId, demoAgentKey, demoMaster, demoSubject } from "./demo-agents.ts";

const DEFAULT_PORT = 8799;

/** One demo identity: everything the client needs, derived, never transferred. */
export type DemoAgentSpec = {
  readonly role: Role;
  readonly ring: number;
  readonly id: string;
  readonly key: Buffer;
  readonly counter: number;
};

/**
 * The three demo agents, derived from the recipe alone.
 *
 * This is the same computation `unity/Assets/Zeus/Scripts/ZeusWire.cs` performs, and the same
 * one `server/agents.ts` performs when the demo arbiter enrols them — three implementations of
 * one recipe, which `tests/unity-demo.test.ts` pins against each other.
 */
export function demoAgents(): DemoAgentSpec[] {
  return DEMO_ROLES.map((role, index) => {
    const counter = index + 1;
    const id = demoAgentId(role, counter);
    return { role, ring: ROLE_RING[role], id, key: demoAgentKey(id), counter };
  });
}

/** One scripted interval of the demo timeline. */
export type DemoPhase = {
  readonly label: string;
  readonly role: Role;
  readonly code: EvidenceCode;
  readonly seconds: number;
};

/** The scripted phases, chosen so the doctrine is visible from the console. */
export const DEMO_PHASES: readonly DemoPhase[] = [
  { label: "CLEAN        allowlist hit (benign)", role: "UMON", code: "XD", seconds: 5 },
  { label: "BEHAVIOURAL  server-side signal alone", role: "SRV", code: "X8", seconds: 6 },
  { label: "STRUCTURAL   foreign write handle", role: "KMOD", code: "X2", seconds: 10 },
];

export type DemoPost = {
  readonly status: number;
  readonly body: string;
};

/**
 * Sign and post one batch, exactly as the Unity client does: canonical string, HMAC over it,
 * `x-zeus-sig` header, JSON array body.
 *
 * The batch carries one principal's events, because the arbiter refuses a batch spanning two
 * agents — a single MAC cannot honestly cover two keys.
 */
export async function postDemoEvent(
  baseUrl: string,
  spec: DemoAgentSpec,
  body: { subject: string; code: EvidenceCode; seq: number; nowMs: number; measurement?: number },
  key: Buffer = spec.key,
  ring: number = spec.ring,
): Promise<DemoPost> {
  const event: IngestEvent = {
    v: PROTOCOL_VERSION,
    a: spec.id,
    k: body.subject,
    s: body.seq,
    t: body.nowMs,
    r: ring as IngestEvent["r"],
    c: body.code,
    m: body.measurement ?? 1,
  };
  const canonical = canonicalEvent(event);
  const sig = createHmac("sha256", key).update(canonical, "utf8").digest("hex");
  const response = await fetch(`${baseUrl}/v1/ingest`, {
    method: "POST",
    headers: { "content-type": "application/json", "x-zeus-sig": sig },
    body: JSON.stringify([event]),
  });
  return { status: response.status, body: await response.text() };
}

/**
 * Play the scripted timeline against a running demo arbiter.
 *
 * Exported so the demo and the test drive the identical code path: what the operator watches
 * on screen is what the suite asserts.
 */
export async function runDemoTimeline(
  baseUrl: string,
  options: { subject: string; perSecond?: number; log?: (line: string) => void; phases?: readonly DemoPhase[] },
): Promise<{ accepted: number; refused: number }> {
  const perSecond = options.perSecond ?? 4;
  const log =
    options.log ??
    ((line: string): void => {
      process.stdout.write(`${line}\n`);
    });
  const phases = options.phases ?? DEMO_PHASES;
  const agents = demoAgents();
  const byRole = new Map<Role, DemoAgentSpec>(agents.map((agent) => [agent.role, agent] as [Role, DemoAgentSpec]));
  const seq = new Map<Role, number>(agents.map((agent) => [agent.role, 0] as [Role, number]));
  const interval = Math.max(50, Math.round(1000 / perSecond));

  let accepted = 0;
  let refused = 0;
  for (const phase of phases) {
    const agent = byRole.get(phase.role);
    if (agent === undefined) continue;
    log(`  ${phase.label.padEnd(34)} ${agent.id.slice(0, 8)} ${phase.seconds}s`);
    const until = Date.now() + phase.seconds * 1000;
    while (Date.now() < until) {
      const next = (seq.get(phase.role) ?? 0) + 1;
      seq.set(phase.role, next);
      const result = await postDemoEvent(baseUrl, agent, {
        subject: options.subject,
        code: phase.code,
        seq: next,
        nowMs: Date.now(),
      });
      if (result.status === 202) accepted += 1;
      else refused += 1;
      await new Promise((resolve) => setTimeout(resolve, interval));
    }
  }
  log(`  accepted ${accepted}, refused ${refused}`);
  return { accepted, refused };
}

async function main(): Promise<void> {
  const argv = process.argv.slice(2);
  const serverOnly = argv.includes("--server-only");
  const portArg = argv.find((argument) => argument.startsWith("--port="));
  const port = portArg === undefined ? DEFAULT_PORT : Number(portArg.slice("--port=".length));

  const provided = process.env["ZEUS_MASTER_KEY"];
  // The demo pins the master, because the ids the Unity client derives depend on it. An
  // operator who already had a key set is told it is being overridden rather than left to
  // wonder why their fleet changed identity.
  const env: NodeJS.ProcessEnv = {
    ...process.env,
    ZEUS_MASTER_KEY: demoMaster().toString("hex"),
    ZEUS_DB: ".zeus-data/unity-demo.db",
    ZEUS_UPLOAD_DIR: ".zeus-data/unity-demo-uploads",
    ZEUS_SESSIONS: "0",
    ZEUS_TPS: "0",
    ZEUS_COOKIE_SECURE: "0",
    NODE_ENV: "development",
  };

  const system = bootstrap({ env, sessions: 0, tps: 0, port });
  const enrolled = DEMO_ROLES.map((role) => system.registry.enroll(role));

  // Self-check before anything is served: if the arbiter's enrolment and the published recipe
  // disagree, every Unity client would be rejected with an indistinguishable 401 and the
  // operator would have no way to tell why. Fail loudly here instead.
  const specs = demoAgents();
  enrolled.forEach((agent, index) => {
    const spec = specs[index];
    const role = DEMO_ROLES[index] ?? "UMON";
    if (spec === undefined || agent.id !== spec.id || !agent.key.equals(spec.key)) {
      process.stderr.write(
        `\n ZEUS demo refused to start: the enrolled ${role} agent does not match the published recipe.\n` +
          " The Unity client derives its id and key from tools/demo-agents.ts; a mismatch makes every batch unauthenticated.\n\n",
      );
      system.store.close();
      process.exit(4);
    }
  });

  const staticDir = existsSync("dist") ? "dist" : null;
  const server = createArbiterServer({
    runtime: system.runtime,
    consoleOrigins: [`http://127.0.0.1:${port}`, `http://localhost:${port}`],
    staticDir,
  });

  server.on("error", (error: NodeJS.ErrnoException) => {
    process.stderr.write(`[unity-demo] ${error.code === "EADDRINUSE" ? `port ${port} is already bound` : error.message}\n`);
    process.exit(2);
  });

  await new Promise<void>((resolve) => server.listen(port, "127.0.0.1", resolve));
  system.runtime.start();

  const line = "-".repeat(72);
  const subject = demoSubject("unity-demo-player");
  process.stdout.write(
    [
      line,
      " ZEUS Unity demo — the real arbiter, three demo agents, no synthetic fleet",
      line,
      ` arbiter       http://127.0.0.1:${port}/v1/ingest`,
      ` console       ${staticDir === null ? `(none — run "npm run build" for the operator console)` : `http://127.0.0.1:${port}/console`}`,
      ` subject       ${subject}`,
      "",
      " demo agents (derived, never transferred):",
      ...specs.map((spec) => `   ${spec.role.padEnd(5)} ring ${String(spec.ring).padStart(2)}  id ${spec.id}`),
      "",
      ` recipe        master = SHA256("${DEMO_PASSPHRASE}")`,
      `               id = HMAC(master, "agent-id:<role>:<counter>")[0..16]`,
      `               key = HMAC(master, "agent-key:<id>")`,
      `               sig = HMAC(key, events.map(canonical).join("\\n"))`,
      "",
      " Unity:        drop unity/Assets/Zeus into the project and set Base Url above.",
      ...(serverOnly ? [" (--server-only: the stand-in client is disabled)"] : []),
      line,
      ...system.notices.map((notice) => ` [!] ${notice}`),
      "",
    ].join("\n"),
  );

  if (provided !== undefined && provided !== env["ZEUS_MASTER_KEY"]) {
    process.stdout.write(" [!] ZEUS_MASTER_KEY was set in the environment and has been replaced by the demo recipe key\n\n");
  }

  if (!serverOnly) {
    process.stdout.write(" playing the demo timeline (Ctrl-C to stop)\n");
    await runDemoTimeline(`http://127.0.0.1:${port}`, { subject });
    process.stdout.write(
      "\n timeline complete — the STRUCTURAL phase should now read FLAGGED on the console.\n" +
        " the arbiter stays up so the console can be read; Ctrl-C to stop.\n\n",
    );
  }

  const shutdown = (): void => {
    system.runtime.stop();
    server.close(() => {
      system.store.close();
      process.exit(0);
    });
    setTimeout(() => process.exit(0), 1_500).unref();
  };
  process.on("SIGINT", shutdown);
  process.on("SIGTERM", shutdown);
}

// Only run when invoked directly, so the test suite can import the timeline above.
const invoked = process.argv[1] === undefined ? "" : path.resolve(process.argv[1]);
if (invoked === fileURLToPath(import.meta.url)) {
  void main();
}
