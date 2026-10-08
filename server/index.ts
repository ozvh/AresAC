/**
 * ARES arbiter bootstrap.
 *
 * Argument parsing, one call to the composition root, and a banner that states exactly
 * what an operator needs to know before trusting the process: which origins may talk to
 * it, where its keys came from, whether the mail relay is configured, and — the line that
 * matters most in production — whether any secret was generated for this process rather
 * than configured. A deployment that lost its `ARES_SESSION_KEY` still works, and an
 * operator who is not told that will find out when everyone is signed out after a deploy.
 *
 * Every generated secret is printed for the operator's own use in the case of the operator
 * token, and stated as generated for the rest. Nothing else is ever written to standard
 * output: no session identifiers, no addresses, no request bodies.
 */
import { readFileSync } from "node:fs";
import { createArbiterServer } from "./http.ts";
import { bootstrap } from "./bootstrap.ts";
import { productionReadiness } from "./prodcheck.ts";

const DEFAULT_PORT = 8787;
const DEFAULT_ORIGINS = "http://127.0.0.1:5173,http://localhost:5173,http://127.0.0.1:8787,http://localhost:8787";

type Options = {
  port: number;
  staticDir: string | null;
  sessions: number;
  tps: number;
  fleetEnabled: boolean;
  seed: number;
};

function parseArgs(argv: readonly string[], env: NodeJS.ProcessEnv): Options {
  const options: Options = {
    port: Number(env["PORT"] ?? DEFAULT_PORT),
    staticDir: null,
    sessions: Number(env["ARES_SESSIONS"] ?? 6),
    tps: Number(env["ARES_TPS"] ?? 60),
    fleetEnabled: true,
    seed: Number(env["ARES_SEED"] ?? 0x5eed),
  };
  for (const arg of argv) {
    if (arg.startsWith("--port=")) options.port = Number(arg.slice("--port=".length));
    else if (arg.startsWith("--serve-static=")) options.staticDir = arg.slice("--serve-static=".length);
    else if (arg.startsWith("--sessions=")) options.sessions = Number(arg.slice("--sessions=".length));
    else if (arg.startsWith("--tps=")) options.tps = Number(arg.slice("--tps=".length));
    else if (arg.startsWith("--seed=")) options.seed = Number(arg.slice("--seed=".length));
    else if (arg === "--no-fleet") options.fleetEnabled = false;
  }
  if (!Number.isInteger(options.port) || options.port < 1 || options.port > 65535) options.port = DEFAULT_PORT;
  if (!Number.isInteger(options.sessions) || options.sessions < 1) options.sessions = 1;
  if (!Number.isFinite(options.tps) || options.tps < 0) options.tps = 0;
  if (!Number.isFinite(options.seed)) options.seed = 0x5eed;
  return options;
}

type TlsMaterial = { readonly cert: Buffer; readonly key: Buffer };

/**
 * TLS material, when the operator has supplied it.
 *
 * The listener binds loopback, so the usual deployment terminates TLS at a proxy and
 * leaves these unset. Setting both makes this process speak HTTPS directly, which is what
 * a single-host deployment needs. Setting exactly one is a configuration error and is
 * refused rather than silently ignored — the failure mode of "TLS was configured but not
 * enabled" is a plaintext listener that looks configured.
 */
function resolveTls(env: NodeJS.ProcessEnv): { material: TlsMaterial | null; error: string | null } {
  const certPath = (env["ARES_TLS_CERT"] ?? "").trim();
  const keyPath = (env["ARES_TLS_KEY"] ?? "").trim();
  if (certPath === "" && keyPath === "") return { material: null, error: null };
  if (certPath === "" || keyPath === "") {
    return { material: null, error: "ARES_TLS_CERT and ARES_TLS_KEY must be set together" };
  }
  try {
    return { material: { cert: readFileSync(certPath), key: readFileSync(keyPath) }, error: null };
  } catch (error) {
    // The path is safe to print; the material is not, and never is.
    return { material: null, error: `TLS material could not be read: ${error instanceof Error ? error.message : "unknown error"}` };
  }
}

function main(): void {
  const options = parseArgs(process.argv.slice(2), process.env);

  const origins = (process.env["ARES_CONSOLE_ORIGINS"] ?? DEFAULT_ORIGINS)
    .split(",")
    .map((entry) => entry.trim())
    .filter((entry) => entry.length > 0);

  const system = bootstrap({
    port: options.port,
    sessions: options.sessions,
    tps: options.tps,
    seed: options.seed,
  });
  const { runtime, auth, uploads, subs, mailer } = system;

  const tls = resolveTls(process.env);
  const readiness = productionReadiness({
    env: process.env,
    cookieSecure: auth.cookieSecure,
    origins,
    tls: tls.material !== null,
  });
  const fatal = [...(tls.error === null ? [] : [tls.error]), ...readiness.fatal];
  if (fatal.length > 0) {
    // Refuse before binding. A process that starts and then reports its problem has
    // already accepted traffic, and the operator who misses one line of a banner has an
    // insecure deployment that their monitoring calls healthy.
    system.store.close();
    process.stderr.write(
      [
        "",
        " ARES refused to start — the production configuration is not safe:",
        ...fatal.map((entry) => ` [!] ${entry}`),
        "",
      ].join("\n"),
    );
    process.exit(3);
  }

  const server = createArbiterServer({
    runtime,
    consoleOrigins: origins,
    staticDir: options.staticDir,
    ...(tls.material === null ? {} : { tls: tls.material }),
  });

  server.on("error", (error: NodeJS.ErrnoException) => {
    if (error.code === "EADDRINUSE") {
      process.stderr.write(`[ares] port ${options.port} is already bound; pass --port=<n>\n`);
      process.exit(2);
    }
    process.stderr.write(`[ares] server error: ${error.message}\n`);
    process.exit(1);
  });

  server.listen(options.port, "127.0.0.1", () => {
    runtime.start();
    if (options.fleetEnabled) system.fleet.start();

    const invariants = system.store.invariants();
    const chain = system.ledger.status();
    const line = "─".repeat(68);

    // Asynchronous because it hashes a password, and it must not block the listen path.
    // The outcome is printed rather than logged, because it is operator state, not a
    // diagnostic, and it is the only place the bootstrap account's existence is announced.
    void auth.ensureBootstrapAdmin(process.env).then((outcome) => {
      process.stdout.write(` administrator  ${outcome}\n`);
    });

    process.stdout.write(
      [
        line,
        " ARES arbiter — authoritative conviction engine",
        line,
        // The scheme is stated rather than assumed: an operator reading `http://` on a
        // listener that is actually speaking TLS would reasonably conclude the opposite of
        // what is true, and this line is the only place the boot says which it is.
        ` listen        ${tls.material === null ? "http" : "https"}://127.0.0.1:${options.port}   (loopback only)`,
        ` agents        ${system.registry.size} provisioned across ${options.sessions} session(s)`,
        ` key idiom     ${system.registry.fingerprint}`,
        ` operator tok  ${process.env["ARES_OPERATOR_TOKEN"] === undefined ? runtime.operatorToken : "from environment (ARES_OPERATOR_TOKEN)"}`,
        ` origins       ${origins.join(" ")}`,
        ` static dir    ${options.staticDir ?? "(none — API only)"}`,
        ` transport     ${tls.material === null ? "http (plaintext — terminate TLS at a proxy)" : "https (TLS on this listener)"}`,
        ` fleet rate    ${options.tps} evt/s target${options.fleetEnabled ? "" : " (fleet disabled)"}`,
        line,
        ` accounts      sqlite schema v${invariants.schemaVersion}  foreign_keys=${invariants.foreignKeys ? "ON" : "OFF"}`,
        ` stores        append-only triggers=${invariants.appendOnlyTriggers}/4  audit records=${system.store.countAudit()}`,
        ` ledger        ${chain.length} sealed, chain ${chain.broken ? `BROKEN at ${String(chain.brokenAt)}` : "verified"}`,
        ` sessions      ${auth.cookieSecure ? "cookie Secure=ON" : "cookie Secure=OFF (fine on loopback, never in production)"}`,
        ` uploads       retention ${uploads.retentionDays} days`,
        ` renewals      notice ${subs.noticeDays} days before each period end`,
        ` mail relay    ${mailer.summary}`,
        ` spool         ${mailer.configured ? "(unused while the relay accepts)" : mailer.spoolPath}`,
        line,
        " Doctrine: capability before account. corroboration before conviction.",
        "           a single behavioural ring may never convict.",
        line,
        ...readiness.warnings.map((warning) => ` [!] ${warning}`),
        ...system.notices.map((notice) => ` [!] ${notice}`),
        "",
      ].join("\n"),
    );
  });

  const shutdown = (signal: string): void => {
    process.stdout.write(`\n[ares] ${signal} — sealing ledger and stopping\n`);
    system.fleet.stop();
    runtime.stop();
    server.close(() => {
      // The database is closed explicitly so a WAL checkpoint happens before exit; an
      // unflushed journal is how a "restart" silently loses the last few audit records.
      system.store.close();
      process.exit(0);
    });
    setTimeout(() => process.exit(0), 1_500).unref();
  };
  process.on("SIGINT", () => shutdown("SIGINT"));
  process.on("SIGTERM", () => shutdown("SIGTERM"));
}

main();
