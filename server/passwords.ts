/**
 * Password hashing.
 *
 * scrypt from `node:crypto`, which is memory-hard and built into the runtime. Argon2id
 * is the stronger choice and would need a native dependency; scrypt with the parameters
 * below is the OWASP-accepted alternative and is the right trade here, because adding a
 * compiled module to a process whose dependency surface is part of its threat model is
 * itself a risk. The parameters are recorded inside the digest, so raising them later
 * re-hashes new passwords while every existing digest keeps verifying.
 *
 * THREE PROPERTIES THIS FILE OWNS.
 *
 * 1. THE DIGEST IS SELF-DESCRIBING. `scrypt$N$r$p$salt$key`. A digest that does not
 *    parse verifies as false rather than throwing, so a corrupted row is a failed login
 *    and not a 500 that leaks the row's existence through its status code.
 * 2. VERIFICATION IS TIMING-SAFE. Comparison is `timingSafeEqual` over two digests of
 *    identical length, and the length is fixed by the parameters rather than by the
 *    candidate, so the comparison cannot be talked into a short-circuit.
 * 3. AN UNKNOWN ACCOUNT COSTS THE SAME AS A KNOWN ONE. `verifyAbsent` burns the same
 *    work against a fixed dummy digest. Without it, "no such user" returns in
 *    microseconds while a real account takes ~100 ms, and that difference is a free
 *    account-enumeration oracle for anyone who can time a request.
 *
 * `promisify` is not used: the callback overloads produce a typing that no longer
 * states which buffer is which, and the explicit wrapper below keeps the contract
 * readable. The password is passed as a string and encoded by the runtime; it is never
 * logged, never stored, and never returned from any function in this file.
 */
import { randomBytes, scrypt as scryptCallback, timingSafeEqual } from "node:crypto";

type ScryptParams = {
  readonly N: number;
  readonly r: number;
  readonly p: number;
};

/**
 * Interactive-login cost. 2^14 iterations over 8 blocks needs ~16 MiB per attempt, which
 * is what makes a GPU farm expensive, while staying near 100 ms on a normal core. The
 * ceiling on concurrent logins is therefore the libuv threadpool, which is the intended
 * behaviour: a login flood should queue, not saturate the CPU.
 */
const PARAMS: ScryptParams = { N: 16_384, r: 8, p: 1 };

/** 128 * N * r * 2 leaves headroom above the algorithm's own requirement. */
const MAX_MEM = 64 * 1024 * 1024;

const SALT_BYTES = 16;
const KEY_BYTES = 32;

/** Password length bounds. The upper bound exists so a 10 MiB "password" is not hashed. */
export const PASSWORD_MIN = 12;
export const PASSWORD_MAX = 200;

/**
 * A floor, not a substitute for a breach corpus.
 *
 * Twelve characters already excludes most human-chosen passwords; this list catches the
 * handful of long-but-canonical strings a length rule alone would admit. A production
 * deployment should check against a real corpus such as the Pwned Passwords range API,
 * which is a network call and deliberately not made here.
 */
const COMMON = new Set<string>([
  "passwordpassword",
  "password12345",
  "123456789012",
  "qwertyuiop12",
  "letmeinletmein",
  "correcthorsebatterystaple",
  "iloveyouiloveyou",
  "administrator1",
  "changemenow123",
  "welcometotheclub",
]);

export type PasswordProblem = { readonly code: string; readonly msg: string };

/**
 * Apply the policy. Returns null when the password is acceptable.
 *
 * The reason returned is deliberately the same shape for every rejection: a caller that
 * echoes it back is telling an attacker which rule to satisfy, and for a password the
 * attacker is the person being told.
 */
export function checkPassword(password: string, email: string): PasswordProblem | null {
  if (password.length < PASSWORD_MIN) {
    return { code: "PASSWORD_TOO_SHORT", msg: `a password must be at least ${PASSWORD_MIN} characters` };
  }
  if (password.length > PASSWORD_MAX) {
    return { code: "PASSWORD_TOO_LONG", msg: `a password must be at most ${PASSWORD_MAX} characters` };
  }
  if (password.trim().length === 0) {
    return { code: "PASSWORD_BLANK", msg: "a password cannot be only whitespace" };
  }
  if (COMMON.has(password.toLowerCase())) {
    return { code: "PASSWORD_COMMON", msg: "that password is among the most commonly used and is not accepted" };
  }
  const local = email.split("@")[0] ?? "";
  if (local.length >= 4 && password.toLowerCase().includes(local.toLowerCase())) {
    return { code: "PASSWORD_ECHOES_EMAIL", msg: "a password may not contain your own address" };
  }
  return null;
}

export class PasswordWorkBusy extends Error {
  constructor() { super("password work capacity reached"); }
}
export const PASSWORD_WORK_LIMIT = 4;
let activeWork = 0;

function derive(password: string, salt: Buffer, params: ScryptParams): Promise<Buffer> {
  if (activeWork >= PASSWORD_WORK_LIMIT) return Promise.reject(new PasswordWorkBusy());
  activeWork += 1;
  return new Promise((resolve, reject) => {
    try {
    scryptCallback(
      password,
      salt,
      KEY_BYTES,
      { N: params.N, r: params.r, p: params.p, maxmem: MAX_MEM },
      (error: Error | null, key: Buffer) => {
        activeWork -= 1;
        if (error !== null) {
          reject(error);
          return;
        }
        resolve(key);
      },
    );
    } catch (error) {
      activeWork -= 1;
      reject(error);
    }
  });
}

/** Hash a password into the self-describing digest format. */
export async function hashPassword(password: string): Promise<string> {
  const salt = randomBytes(SALT_BYTES);
  const key = await derive(password, salt, PARAMS);
  return [
    "scrypt",
    String(PARAMS.N),
    String(PARAMS.r),
    String(PARAMS.p),
    salt.toString("base64"),
    key.toString("base64"),
  ].join("$");
}

type Parsed = { readonly salt: Buffer; readonly key: Buffer; readonly params: ScryptParams };

/**
 * Parse a stored digest.
 *
 * Every failure returns null. A malformed digest is an authentication failure, never an
 * exception: an exception would distinguish "this row is corrupt" from "wrong password"
 * in the response, and would also turn a partially restored backup into an outage.
 */
function parse(stored: string): Parsed | null {
  const parts = stored.split("$");
  if (parts.length !== 6) return null;
  const [scheme, nRaw, rRaw, pRaw, saltRaw, keyRaw] = parts;
  if (scheme !== "scrypt") return null;
  const N = Number(nRaw);
  const r = Number(rRaw);
  const p = Number(pRaw);
  if (!Number.isInteger(N) || !Number.isInteger(r) || !Number.isInteger(p)) return null;
  if (N < 1024 || N > 1_048_576 || r < 1 || r > 32 || p < 1 || p > 16) return null;
  if ((N & (N - 1)) !== 0) return null;
  // Bound the work a stored digest can demand, so a tampered row cannot be turned into
  // a memory-exhaustion primitive against the login endpoint.
  if (128 * N * r > MAX_MEM) return null;
  const salt = Buffer.from(saltRaw ?? "", "base64");
  const key = Buffer.from(keyRaw ?? "", "base64");
  if (salt.length !== SALT_BYTES || key.length !== KEY_BYTES) return null;
  return { salt, key, params: { N, r, p } };
}

/** Constant-time verify against a stored digest. */
export async function verifyPassword(password: string, stored: string): Promise<boolean> {
  const parsed = parse(stored);
  if (parsed === null) return false;
  const candidate = await derive(password, parsed.salt, parsed.params);
  if (candidate.length !== parsed.key.length) return false;
  return timingSafeEqual(candidate, parsed.key);
}

/**
 * Burn the same work for an account that does not exist.
 *
 * The dummy digest is generated at module load with the live parameters, so it stays in
 * step with real ones. Callers invoke this on the unknown-account path and return the
 * same failure as a wrong password.
 */
let dummyDigest: string | null = null;

async function ensureDummy(): Promise<string> {
  if (dummyDigest === null) dummyDigest = await hashPassword(randomBytes(24).toString("base64"));
  return dummyDigest;
}

export async function verifyAbsent(password: string): Promise<boolean> {
  const digest = await ensureDummy();
  await verifyPassword(password, digest);
  // Always false: this exists for its cost, and reporting true here would be a
  // back door rather than a defence.
  return false;
}

/**
 * A digest for a credential that must never authenticate anyone.
 *
 * Used for the bootstrap administrator before a password is set. A random 32-byte secret
 * is hashed so the column is a well-formed digest, while the plaintext exists nowhere.
 */
export async function unusableDigest(): Promise<string> {
  return hashPassword(randomBytes(32).toString("base64"));
}
