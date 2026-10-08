/**
 * Load harness. MEASURES the ingest path; it does not assert it.
 *
 * It drives the real HTTP surface of a real arbiter in a real process — socket,
 * schema validation, MAC verification, replay and provenance checks, rate limiter,
 * state machine — and reports what actually happened: achieved rate, per-request
 * latency percentiles, the arbiter's own per-sample adjudication cost, and the full
 * refusal breakdown.
 *
 * Two phases, because they answer different questions:
 *
 *   PROBE  a small fleet pushed far past its per-agent budget. It should be refused
 *          at the token bucket, and the measurement is whether refusals are clean.
 *   LOAD   enough principals that the rate limiter is not the binding constraint,
 *          so the number reported is the cost of the pipeline itself.
 *
 * Run:  npm run load
 *       npm run load -- --agents=240 --target=8000 --seconds=6
 */
import { createHash } from "node:crypto";
import type { AddressInfo } from "node:net";
import {
  LIMITS,
  PROTOCOL_VERSION,
  canonicalEvent,
  type EvidenceCode,
  type IngestEvent,
  type RingId,
  type Role,
  type SnapshotResponse,
} from "../shared/protocol.ts";
import { AgentRegistry, signEvent, type Agent } from "../server/agents.ts";
import { Auth } from "../server/auth.ts";
import { Fleet } from "../server/fleet.ts";
import { createArbiterServer } from "../server/http.ts";
import { Ledger } from "../server/ledger.ts";
import { Mailer } from "../server/mailer.ts";
import { Arbiter } from "../server/machine.ts";
import { RequestIntake } from "../server/requests.ts";
import { Runtime } from "../server/runtime.ts";
import { Broadcaster } from "../server/sse.ts";
import { Subscriptions } from "../server/subscriptions.ts";
import { UploadService, UploadStore } from "../server/uploads.ts";
import { Store } from "../server/db.ts";

/**
 * The runtime this harness needs, assembled so the harness itself changes nothing about
 * the system under measurement.
 *
 * The account surfaces are present but inert: an in-memory database, no relay credential,
 * and upload storage inside the temporary directory. The measurement is of the ingest path,
 * and nothing here may write to disk or emit mail while it is taken.
 */
function makeRuntime(parts: {
  arbiter: Arbiter;
  ledger: Ledger;
  bus: Broadcaster;
  registry: AgentRegistry;
  fleet: Fleet;
}): Runtime {
  const store = new Store({ file: ":memory:", now: () => Date.now() });
  const mailer = new Mailer({
    apiKey: "",
    from: "ARES Load Harness <offline@invalid>",
    recipient: "offline@invalid",
    endpoint: "http://127.0.0.1:1/emails",
    spoolPath: "offline-requests.log",
    timeoutMs: 50,
  });
  return new Runtime({
    ...parts,
    requests: new RequestIntake({ mailer, ledger: parts.ledger }),
    auth: new Auth({ store, sessionKey: Buffer.alloc(32, 3), cookieSecure: false, now: () => Date.now() }),
    store,
    subs: new Subscriptions({ store, mailer, now: () => Date.now(), noticeDays: 14 }),
    uploads: new UploadService({ store, files: new UploadStore("offline-uploads"), now: () => Date.now(), retentionDays: 30 }),
    operatorToken: "x".repeat(48),
  });
}

type Options = {
  agents: number;
  target: number;
  seconds: number;
  concurrency: number;
  batch: number;
  probeAgents: number;
};

function parseArgs(argv: readonly string[]): Options {
  const options: Options = {
    agents: 240,
    target: 8_000,
    seconds: 6,
    concurrency: 48,
    batch: 16,
    probeAgents: 24,
  };
  for (const arg of argv) {
    if (arg.startsWith("--agents=")) options.agents = Number(arg.slice(9));
    else if (arg.startsWith("--target=")) options.target = Number(arg.slice(9));
    else if (arg.startsWith("--seconds=")) options.seconds = Number(arg.slice(10));
    else if (arg.startsWith("--concurrency=")) options.concurrency = Number(arg.slice(14));
    else if (arg.startsWith("--batch=")) options.batch = Number(arg.slice(8));
    else if (arg.startsWith("--probe-agents=")) options.probeAgents = Number(arg.slice(15));
  }
  if (!Number.isFinite(options.target) || options.target < 1) options.target = 1_000;
  if (!Number.isFinite(options.seconds) || options.seconds < 1) options.seconds = 4;
  if (!Number.isFinite(options.agents) || options.agents < 3) options.agents = 3;
  if (!Number.isFinite(options.concurrency) || options.concurrency < 1) options.concurrency = 8;
  if (!Number.isFinite(options.batch) || options.batch < 1) options.batch = 1;
  options.batch = Math.min(options.batch, LIMITS.batchMax);
  return options;
}

const ROLES: readonly Role[] = ["UMON", "KMOD", "SRV"];
const RING_OF: Readonly<Record<Role, RingId>> = { UMON: 3, KMOD: 0, SRV: -1 };
/** One code per ring that the server-side catalogue actually authorises for it. */
const CODES: Readonly<Record<Role, EvidenceCode>> = { UMON: "X4", KMOD: "X6", SRV: "X8" };

function percentile(sorted: readonly number[], fraction: number): number {
  if (sorted.length === 0) return 0;
  const idx = Math.min(sorted.length - 1, Math.floor(sorted.length * fraction));
  return sorted[idx] ?? 0;
}

type Approach = {
  label: string;
  agents: number;
  target: number;
  seconds: number;
  concurrency: number;
  batch: number;
};

type Principal = { agent: Agent; role: Role; digest: string; seq: number };

function sleep(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

async function run(base: string, registry: AgentRegistry, setup: Approach): Promise<void> {
  const principals: Principal[] = Array.from({ length: setup.agents }, (_unused, i) => {
    const role = ROLES[i % ROLES.length] ?? "UMON";
    return {
      agent: registry.enroll(role),
      role,
      digest: createHash("sha256").update(`subject:${i % 40}`).digest("hex").slice(0, 32),
      seq: 0,
    };
  });

  const statusCounts = new Map<number, number>();
  const latencies: number[] = [];
  let requests = 0;
  let sent = 0;
  let accepted = 0;

  // Each principal is owned by exactly one worker, so a principal's sequence numbers
  // are issued in order. Sharing a principal across workers would let a later batch
  // reach the arbiter first and be refused as a replay — manufacturing a defence
  // failure out of the harness itself.
  const owned: Principal[][] = Array.from({ length: setup.concurrency }, () => []);
  for (let i = 0; i < principals.length; i += 1) {
    owned[i % setup.concurrency]?.push(principals[i] as Principal);
  }

  const startedAt = Date.now();
  const deadline = startedAt + setup.seconds * 1000;
  const batch = setup.batch;
  // Closed-loop pacing: requests are only issued when the target rate says they are
  // due, so the offered rate is controlled rather than whatever the event loop gives.
  const expectedRequestsPerSecond = setup.target / batch;
  let issued = 0;

  async function oneRequest(principal: Principal): Promise<void> {
    const now = Date.now();
    const events: IngestEvent[] = [];
    for (let i = 0; i < batch; i += 1) {
      principal.seq += 1;
      events.push({
        v: PROTOCOL_VERSION,
        a: principal.agent.id,
        k: principal.digest,
        s: principal.seq,
        t: now,
        r: RING_OF[principal.role],
        c: CODES[principal.role],
        m: 1,
      });
    }
    sent += events.length;
    const started = performance.now();
    try {
      const res = await fetch(`${base}/v1/ingest`, {
        method: "POST",
        headers: {
          "content-type": "application/json",
          "x-ares-sig": signEvent(principal.agent.key, events.map((e) => canonicalEvent(e)).join("\n")),
        },
        body: JSON.stringify(events),
      });
      // Drain the body before timing, so the measurement covers the whole exchange.
      await res.arrayBuffer();
      latencies.push(performance.now() - started);
      statusCounts.set(res.status, (statusCounts.get(res.status) ?? 0) + 1);
      requests += 1;
      if (res.status === 202) accepted += events.length;
    } catch {
      latencies.push(performance.now() - started);
      statusCounts.set(0, (statusCounts.get(0) ?? 0) + 1);
    }
  }

  await Promise.all(
    owned.map(async (mine) => {
      if (mine.length === 0) return;
      let cursor = 0;
      for (;;) {
        if (Date.now() >= deadline) return;
        const elapsedSeconds = (Date.now() - startedAt) / 1000;
        if (issued >= elapsedSeconds * expectedRequestsPerSecond) {
          await sleep(1);
          continue;
        }
        issued += 1;
        const principal = mine[cursor % mine.length];
        cursor += 1;
        if (principal === undefined) return;
        await oneRequest(principal);
      }
    }),
  );
  const elapsed = (Date.now() - startedAt) / 1000;

  const snap = (await (await fetch(`${base}/v1/snapshot`)).json()) as SnapshotResponse;
  latencies.sort((a, b) => a - b);

  const statuses = [...statusCounts.entries()].sort((a, b) => a[0] - b[0]);
  const statusText = statuses
    .map(([status, n]) => `${status === 0 ? "ERR" : status}:${n}`)
    .join("  ");

  process.stdout.write(
    [
      "",
      `── ${setup.label} ${"─".repeat(Math.max(0, 58 - setup.label.length))}`,
      `  principals          ${principals.length} (${setup.agents / 3} sessions across 3 rings)`,
      `  target rate         ${setup.target.toLocaleString("en-US")} evt/s  for ${setup.seconds}s`,
      `  events submitted    ${sent.toLocaleString("en-US")}   (${(sent / elapsed).toFixed(0)} evt/s offered)`,
      `  events accepted     ${accepted.toLocaleString("en-US")}   (${(accepted / elapsed).toFixed(0)} evt/s admitted)`,
      `  requests            ${requests.toLocaleString("en-US")}   (${(requests / elapsed).toFixed(0)}/s, ${setup.concurrency} in flight)`,
      `  request latency     p50 ${percentile(latencies, 0.5).toFixed(2)}ms   p95 ${percentile(latencies, 0.95).toFixed(2)}ms   p99 ${percentile(latencies, 0.99).toFixed(2)}ms`,
      `  arbiter adj p95     ${snap.counters.p95}us per sample`,
      `  http status         ${statusText}`,
      `  arbiter counters    rx ${snap.counters.rx.toLocaleString("en-US")}  rej ${snap.counters.rej}  rl ${snap.counters.rl}  sig ${snap.counters.sig}  rpy ${snap.counters.rpy}  spf ${snap.counters.spf}`,
      `  refusal rate        ${(((sent - accepted) / Math.max(1, sent)) * 100).toFixed(2)}% of offered samples`,
      `  subjects tracked    ${snap.counters.subj}   evicted ${snap.counters.evicted}   convictions ${snap.counters.conv}`,
      `  ledger chain        ${snap.chain.sealed} sealed, ${snap.chain.broken ? "BROKEN" : "verified"}`,
      `  arbiter event rate  ${snap.counters.tps} evt/s accepted (1 observer attached)`,
    ].join("\n") + "\n",
  );
}

async function main(): Promise<void> {
  const options = parseArgs(process.argv.slice(2));
  const registry = new AgentRegistry(Buffer.alloc(32, 0x5a));
  const ledger = new Ledger();
  const arbiter = new Arbiter(ledger);
  const bus = new Broadcaster(LIMITS.replayRing);
  const fleet = new Fleet(registry, { sessions: 1, tps: 0, origin: "http://127.0.0.1:1", seed: 1 });
  const runtime = makeRuntime({ arbiter, ledger, bus, registry, fleet });
  const server = createArbiterServer({ runtime, consoleOrigins: [], staticDir: null });

  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
  const port = (server.address() as AddressInfo).port;
  const base = `http://127.0.0.1:${port}`;
  runtime.start();

  process.stdout.write(`\nARES ingest load harness — arbiter on ${base} (fleet disabled)\n`);

  await run(base, registry, {
    label: "PROBE — small fleet, pushed past its budget",
    agents: options.probeAgents,
    target: options.target,
    seconds: Math.max(2, Math.round(options.seconds / 2)),
    concurrency: options.concurrency,
    batch: options.batch,
  });

  runtime.stop();
  await new Promise<void>((resolve) => server.close(() => resolve()));

  // Fresh process-level state for the load phase, so the probe's refusals cannot
  // flatter or distort the throughput numbers.
  const registry2 = new AgentRegistry(Buffer.alloc(32, 0x5b));
  const ledger2 = new Ledger();
  const arbiter2 = new Arbiter(ledger2);
  const bus2 = new Broadcaster(LIMITS.replayRing);
  const fleet2 = new Fleet(registry2, { sessions: 1, tps: 0, origin: "http://127.0.0.1:1", seed: 1 });
  const runtime2 = makeRuntime({ arbiter: arbiter2, ledger: ledger2, bus: bus2, registry: registry2, fleet: fleet2 });
  const server2 = createArbiterServer({ runtime: runtime2, consoleOrigins: [], staticDir: null });
  await new Promise<void>((resolve) => server2.listen(0, "127.0.0.1", resolve));
  const port2 = (server2.address() as AddressInfo).port;
  runtime2.start();
  await run(`http://127.0.0.1:${port2}`, registry2, {
    label: "LOAD — enough principals that rate limiting is not binding",
    agents: options.agents,
    target: options.target,
    seconds: options.seconds,
    concurrency: options.concurrency,
    batch: options.batch,
  });

  runtime2.stop();
  await new Promise<void>((resolve) => server2.close(() => resolve()));
  process.stdout.write("\n");
  process.exit(0);
}

main().catch((error: unknown) => {
  process.stderr.write(`load harness failed: ${String(error)}\n`);
  process.exit(1);
});
