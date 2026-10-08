/**
 * Production readiness.
 *
 * The controls in this system are only as good as the deployment that hosts them: a
 * hardened session cookie is pointless when the process is started without the flag that
 * sets it. So the configuration is checked once, at boot, against the claims the project
 * makes, and a deployment that is actually insecure is refused rather than advised.
 *
 * The split matters:
 *
 *  - FATAL findings stop the process. They are the ones where the running system would
 *    contradict a guarantee it makes to users, and where continuing would quietly become
 *    the worst outcome: an insecure deployment that looks healthy in a monitor.
 *  - WARNINGS are printed and the process starts. They are real risks that depend on
 *    topology the process cannot see — whether a proxy terminates TLS, for example — and
 *    refusing to start over them would push operators toward disabling the check.
 *
 * Nothing here reads a file or opens a socket: it is a pure function of the environment
 * and two facts the caller already has. That is what makes it testable, and a check that
 * is not tested is a check that rots.
 */
import { PASSWORD_MIN } from "./passwords.ts";

export type ReadinessInput = {
  readonly env: NodeJS.ProcessEnv;
  /** Whether the session cookie will carry `Secure`. */
  readonly cookieSecure: boolean;
  /** Origins permitted to call the API from a browser context. */
  readonly origins: readonly string[];
  /** Whether this listener also speaks TLS. */
  readonly tls: boolean;
};

export type Readiness = {
  readonly production: boolean;
  /** Findings that must stop the process. */
  readonly fatal: readonly string[];
  /** Findings for the operator that do not stop the process. */
  readonly warnings: readonly string[];
};

function flag(env: NodeJS.ProcessEnv, name: string): boolean {
  return (env[name] ?? "").trim() === "1";
}

/**
 * Production is claimed by either variable. `NODE_ENV` is the convention; `ZEUS_ENV`
 * exists because a platform that rewrites `NODE_ENV` should not be able to silently
 * demote a deployment to development and switch these checks off.
 */
export function isProduction(env: NodeJS.ProcessEnv): boolean {
  const node = (env["NODE_ENV"] ?? "").trim().toLowerCase();
  const zeus = (env["ZEUS_ENV"] ?? "").trim().toLowerCase();
  return node === "production" || zeus === "production";
}

/** The shape `bootstrap` requires of a hex secret, restated where readiness can see it. */
function hex64(value: string | undefined): boolean {
  return typeof value === "string" && /^[0-9a-f]{64}$/.test(value.trim());
}

/**
 * An origin that is plaintext and not loopback.
 *
 * Loopback is exempt because a browser on the same host is not on the network; anything
 * else over `http://` is an origin whose cookies and bodies cross a wire in clear text.
 */
function plaintextRemoteOrigin(origin: string): boolean {
  let parsed: URL;
  try {
    parsed = new URL(origin);
  } catch {
    return true;
  }
  if (parsed.protocol !== "http:") return false;
  const host = parsed.hostname.replace(/^\[|\]$/g, "");
  return !(host === "127.0.0.1" || host === "::1" || host === "localhost");
}

/**
 * The secrets that must be configured rather than generated.
 *
 * A generated key is safe in the sense that nobody can guess it, and unsafe in the sense
 * that every restart invalidates all sessions, the enrolled fleet changes identity, and —
 * the reason this is fatal rather than a notice — the value is printed to the boot banner,
 * where it lands in a supervisor's log file.
 */
function secretFindings(env: NodeJS.ProcessEnv): string[] {
  const findings: string[] = [];
  if (!hex64(env["ZEUS_SESSION_KEY"])) {
    findings.push("ZEUS_SESSION_KEY is unset or is not 64 hex characters: sessions would be invalidated by the next restart");
  }
  if (!hex64(env["ZEUS_MASTER_KEY"])) {
    findings.push("ZEUS_MASTER_KEY is unset or is not 64 hex characters: the enrolled agent fleet would change identity on the next restart");
  }
  const token = env["ZEUS_OPERATOR_TOKEN"];
  if (typeof token !== "string" || token.trim().length < 32) {
    findings.push("ZEUS_OPERATOR_TOKEN is unset or shorter than 32 characters: the control-plane token would be regenerated on every boot and printed for an operator to copy");
  }
  return findings;
}

export function productionReadiness(input: ReadinessInput): Readiness {
  const { env, cookieSecure, origins, tls } = input;
  const production = isProduction(env);
  const fatal: string[] = [];
  const warnings: string[] = [];

  const bootstrapPassword = (env["ZEUS_BOOTSTRAP_ADMIN_PASSWORD"] ?? "").trim();

  if (production) {
    if (!cookieSecure) {
      fatal.push("ZEUS_COOKIE_SECURE is not 1 while NODE_ENV is production: the session cookie would cross the network without the Secure flag");
    }
    fatal.push(...secretFindings(env));
    for (const origin of origins) {
      if (plaintextRemoteOrigin(origin)) {
        fatal.push(`ZEUS_CONSOLE_ORIGINS admits ${origin}: an origin that is not loopback and not https may call this API with credentials sent in clear text`);
      }
    }
    if (bootstrapPassword !== "" && bootstrapPassword.length < PASSWORD_MIN) {
      fatal.push(`ZEUS_BOOTSTRAP_ADMIN_PASSWORD is shorter than ${PASSWORD_MIN} characters`);
    }
    if (bootstrapPassword === "") {
      warnings.push("ZEUS_BOOTSTRAP_ADMIN_PASSWORD is unset: no administrator account can be created, so the review console has no authorised reader");
    }
    if (!tls) {
      warnings.push("no TLS material is configured on this listener: terminate TLS at a reverse proxy, or set ZEUS_TLS_CERT and ZEUS_TLS_KEY");
    }
    if (!flag(env, "ZEUS_TRUST_PROXY")) {
      warnings.push("ZEUS_TRUST_PROXY is not 1: behind a reverse proxy every client keys to the same rate-limit bucket and the audit trail records the proxy as the source");
    }
    if (!tls && origins.every((origin) => origin.startsWith("http://"))) {
      warnings.push("every permitted origin is plaintext http: credentials would only be protected by the transport being loopback");
    }
  } else {
    warnings.push(
      "environment is not production: the refusing checks are advisory. Set NODE_ENV=production (or ZEUS_ENV=production) to have an insecure configuration stop the process.",
    );
    if (!tls) {
      warnings.push("no TLS material is configured; this is expected on loopback and unsafe anywhere else");
    }
  }

  return { production, fatal, warnings };
}

/** Re-exported so a caller can size a bootstrap credential without importing the hasher. */
export const BOOTSTRAP_PASSWORD_MIN = PASSWORD_MIN;
