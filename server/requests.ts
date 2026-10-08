/**
 * Build-request intake.
 *
 * This is the second boundary in the system, and the only unauthenticated one that
 * causes an outbound side effect. `validate.ts` guards the telemetry path, where the
 * sender is an enrolled principal holding a MAC key; this file guards the public path,
 * where the sender is a stranger and there is no principal to charge anything to. So
 * the fencing is different: not identity, but bounded shape, bounded velocity, and a
 * fixed destination that the submitter cannot name.
 *
 * Four rules hold here.
 *
 * 1. THE RECIPIENT IS NOT IN THE PAYLOAD. It comes from the relay's own configuration.
 *    A contact form that lets the caller choose the destination is an open mail relay
 *    with extra steps.
 * 2. THE CLOSED KEY SET IS ENFORCED ON A PUBLIC ENDPOINT TOO. Same reasoning as
 *    `validate.ts`: a field the schema does not model cannot ride along into an audit
 *    record or a mail body.
 * 3. VELOCITY IS CHARGED PER SOURCE *AND* PROCESS-WIDE. Per-source alone is defeated by
 *    a spray across addresses; process-wide alone lets one caller starve every other.
 *    Both buckets must clear.
 * 4. REFUSED SUBMISSIONS ARE NOT SEALED. The ledger is a bounded tail of the decisions
 *    that matter, and an anonymous caller must not be able to push genuine verdict
 *    records out of it. Traps and refusals are counted, not sealed; only a request that
 *    was actually handed to the relay earns a record.
 */
import { createHash, randomBytes } from "node:crypto";
import {
  API_ERROR_CODES,
  BUILD_PROFILES,
  REQUEST_KEYS,
  REQUEST_LIMITS,
  isBuildProfile,
  type ApiErrorCode,
  type BuildRequestInput,
  type BuildProfile,
  type RequestRelayState,
  type RequestStats,
} from "../shared/protocol.ts";
import { Ledger } from "./ledger.ts";
import { Limiter } from "./limiter.ts";
import { Mailer, type MailMessage } from "./mailer.ts";

export type SubmitOutcome =
  | { readonly ok: true; readonly ref: string }
  | { readonly ok: false; readonly code: ApiErrorCode; readonly msg: string };

export type ParseOutcome =
  | { readonly ok: true; readonly input: BuildRequestInput }
  | { readonly ok: false; readonly code: ApiErrorCode; readonly msg: string };

/**
 * Deliberately permissive about the local part and strict about shape. The only
 * address this system ever transmits is a header and a reply-to, never an SMTP
 * envelope command, so over-strict RFC 5322 validation buys nothing and rejects real
 * addresses — the classic mistake that makes a contact form refuse legitimate mail.
 */
const EMAIL = /^[A-Za-z0-9._%+-]{1,64}@[A-Za-z0-9-]{1,63}(?:\.[A-Za-z0-9-]{1,63})+$/;

/**
 * Control characters, per field policy.
 *
 * The strict form forbids every control character including newline: it guards the
 * fields that end up in a mail header or an audit record, where a newline is structure
 * an attacker would be supplying. The relaxed form is used for the free-text note
 * only, and it still forbids carriage return and every other control character — a
 * note is allowed to be several lines, it is not allowed to contain a byte that
 * rewrites how the message reads.
 */
const CONTROL_STRICT = /[\u0000-\u001f\u007f]/;
const CONTROL_MULTILINE = /[\u0000-\u0009\u000b-\u001f\u007f]/;
const MAX_DWELL_MS = 86_400_000;

const ERROR_SET: ReadonlySet<string> = new Set<string>(API_ERROR_CODES);

function fail(code: ApiErrorCode, msg: string): ParseOutcome {
  return { ok: false, code, msg };
}

function isPlainObject(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

/**
 * Reject a value that cannot be a legitimate field.
 *
 * `multiline` is opt-in and is passed only for the free-text note. Everything else
 * gets the strict rule, because everything else can reach a header.
 */
function text(value: unknown, field: string, max: number, multiline = false): string | ParseOutcome {
  if (typeof value !== "string") return fail("SCHEMA", `${field} must be a string`);
  const trimmed = value.trim();
  if (trimmed.length > max) return fail("SCHEMA", `${field} exceeds ${max} characters`);
  if ((multiline ? CONTROL_MULTILINE : CONTROL_STRICT).test(trimmed)) {
    return fail("SCHEMA", `${field} contains control characters`);
  }
  return trimmed;
}

function wasFailure(value: string | ParseOutcome): value is ParseOutcome {
  return typeof value !== "string";
}

/**
 * Shape validation. Every field is a bounded primitive; there are no nested objects,
 * no arrays and no coercion, so the value handed to the intake policy is exactly the
 * value the schema describes.
 */
export function parseBuildRequest(raw: string): ParseOutcome {
  if (raw.length > REQUEST_LIMITS.bodyBytes) {
    return fail("TOO_LARGE", `body ${raw.length} > ${REQUEST_LIMITS.bodyBytes}`);
  }
  if (raw.length === 0) return fail("SCHEMA", "empty body");

  let parsed: unknown;
  try {
    parsed = JSON.parse(raw);
  } catch {
    return fail("MALFORMED", "body is not JSON");
  }

  if (!isPlainObject(parsed)) return fail("SCHEMA", "body must be an object");

  const keys = Object.keys(parsed);
  if (keys.length !== REQUEST_KEYS.length) return fail("SCHEMA", `field count ${keys.length}`);
  for (const key of REQUEST_KEYS) {
    if (!Object.hasOwn(parsed, key)) return fail("SCHEMA", `missing field ${key}`);
  }
  if (keys.length !== new Set(keys).size) return fail("SCHEMA", "duplicate fields");

  const name = text(parsed["nm"], "nm", REQUEST_LIMITS.nameMax);
  if (wasFailure(name)) return name;
  const email = text(parsed["em"], "em", REQUEST_LIMITS.emailMax);
  if (wasFailure(email)) return email;
  const org = text(parsed["org"], "org", REQUEST_LIMITS.orgMax);
  if (wasFailure(org)) return org;
  // The only field permitted to contain a newline. A note is prose; refusing a
  // two-paragraph note because it has a line break in it would reject real requests,
  // which is its own kind of failure.
  const note = text(parsed["msg"], "msg", REQUEST_LIMITS.noteMax, true);
  if (wasFailure(note)) return note;
  const trap = text(parsed["hp"], "hp", 200);
  if (wasFailure(trap)) return trap;

  const tgt = parsed["tgt"];
  if (!isBuildProfile(tgt)) return fail("SCHEMA", "tgt is not a known build channel");

  const el = parsed["el"];
  if (typeof el !== "number" || !Number.isInteger(el) || el < 0 || el > MAX_DWELL_MS) {
    return fail("SCHEMA", "el is not a plausible dwell");
  }

  if (name.length < REQUEST_LIMITS.nameMin) return fail("SCHEMA", "nm is too short");
  if (!EMAIL.test(email)) return fail("SCHEMA", "em is not an address");
  if (note.length < REQUEST_LIMITS.noteMin) return fail("SCHEMA", "msg is too short");

  return { ok: true, input: { nm: name, em: email, org, tgt, msg: note, hp: trap, el } };
}

/**
 * A stable, non-reversing reference for one address.
 *
 * The ledger records this rather than the address itself: the console's chain-of-custody
 * panel is read by whoever is at the console, and an operator does not need a stranger's
 * inbox address rendered in an audit row to audit the intake. The digest is enough to
 * recognise that two records describe the same requester, which is all auditing needs.
 */
function addressDigest(address: string): string {
  return createHash("sha256").update(address.toLowerCase(), "utf8").digest("hex").slice(0, 12);
}

/** The channel a request asks for, rendered for a subject line. Closed set, so this is total. */
function profileNote(profile: BuildProfile): string {
  switch (profile) {
    case "RETAIL":
      return "signed retail build";
    case "DEVELOPMENT":
      return "development build";
    case "SOURCE":
      return "source distribution";
    case "EVALUATION":
      return "time-limited evaluation build";
    default: {
      const exhaustive: never = profile;
      return String(exhaustive);
    }
  }
}

function compose(input: BuildRequestInput, ref: string, source: string, now: number): MailMessage {
  const lines = [
    "ARES build request",
    "",
    `ref        ${ref}`,
    `received   ${new Date(now).toISOString()}`,
    `channel    ${input.tgt} (${profileNote(input.tgt)})`,
    "",
    "--- requester ---",
    `callsign   ${input.nm}`,
    `reply      ${input.em}`,
    `org        ${input.org === "" ? "-" : input.org}`,
    `source     ${source}`,
    "",
    "--- note ---",
    input.msg,
    "",
    "--- end ---",
    "Reply directly to this message to answer the requester.",
    "",
  ];
  return {
    to: "",
    from: "",
    replyTo: input.em,
    subject: `[ARES] build request ${input.tgt} // ${input.nm}`,
    text: lines.join("\n"),
  };
}

export class RequestIntake {
  readonly #mailer: Mailer;
  readonly #ledger: Ledger;
  readonly #buckets = new Limiter();
  /** Dedupe: one source asking twice for the same address is one request. */
  readonly #recent = new Map<string, { at: number; ref: string }>();
  #stat: RequestStats = {
    accepted: 0,
    refused: 0,
    throttled: 0,
    trapped: 0,
    duplicates: 0,
    delivered: 0,
    spooled: 0,
    failed: 0,
  };

  constructor(args: { readonly mailer: Mailer; readonly ledger: Ledger }) {
    this.#mailer = args.mailer;
    this.#ledger = args.ledger;
  }

  get mailer(): Mailer {
    return this.#mailer;
  }

  stats(): RequestStats {
    return { ...this.#stat };
  }

  get trackedSources(): number {
    return this.#recent.size;
  }

  /**
   * Admit, then relay.
   *
   * Order matters: shape, then honeypot, then dwell, then velocity, then dedupe, then
   * the relay. Velocity is charged before dedupe so a repeat cannot be used to launder
   * an unlimited number of attempts into one budget.
   */
  async submit(raw: string, source: string, now: number): Promise<SubmitOutcome> {
    const parsed = parseBuildRequest(raw);
    if (!parsed.ok) {
      this.#stat.refused += 1;
      return { ok: false, code: parsed.code, msg: parsed.msg };
    }
    const input = parsed.input;
    const ref = randomBytes(4).toString("hex");

    // Honeypot. The response is a plain refusal rather than a fabricated success: a
    // system whose audit trail is meant to be trustworthy does not get to write
    // fiction into it, and a scan that learns only "refused" learns nothing useful.
    if (input.hp.length > 0) {
      this.#stat.trapped += 1;
      return { ok: false, code: "SCHEMA", msg: "submission refused" };
    }

    if (input.el < REQUEST_LIMITS.dwellMs) {
      this.#stat.refused += 1;
      return { ok: false, code: "SCHEMA", msg: "submission refused" };
    }

    // Two independent buckets. Both must clear.
    const perSource = REQUEST_LIMITS.sourcePerMin / 60;
    const overall = REQUEST_LIMITS.globalPerMin / 60;
    if (!this.#buckets.take(`src:${source}`, now, perSource, REQUEST_LIMITS.sourceBurst)) {
      this.#stat.throttled += 1;
      return { ok: false, code: "RATE", msg: "submission velocity exceeded" };
    }
    if (!this.#buckets.take("src:__global__", now, overall, REQUEST_LIMITS.globalBurst)) {
      this.#stat.throttled += 1;
      return { ok: false, code: "RATE", msg: "submission velocity exceeded" };
    }

    const dedupeKey = `${source}|${input.em.toLowerCase()}`;
    const prior = this.#recent.get(dedupeKey);
    if (prior !== undefined && now - prior.at < REQUEST_LIMITS.dedupeMs) {
      // Answering with the original reference is the honest response: the request is
      // already in the operator's queue, and sending it twice would put two identical
      // requests in front of a human being who has to triage them.
      this.#stat.duplicates += 1;
      return { ok: true, ref: prior.ref };
    }
    this.#remember(dedupeKey, { at: now, ref });

    const message = compose(input, ref, source, now);
    const outcome = await this.#mailer.deliver({
      ...message,
      to: this.#mailer.recipient,
      from: this.#mailer.from,
    });

    this.#stat.accepted += 1;
    if (outcome.relay === "DELIVERED") this.#stat.delivered += 1;
    else if (outcome.relay === "SPOOLED") this.#stat.spooled += 1;
    else this.#stat.failed += 1;

    // Only a request that actually reached the relay is worth sealing. The record
    // carries the relay's verdict because that is the fact an operator needs and the
    // requester is never told.
    const relay: RequestRelayState = outcome.relay;
    this.#ledger.append("REQUEST", "-", `REQ ${relay} ${input.tgt} ${ref} sha:${addressDigest(input.em)}`, now);

    return { ok: true, ref };
  }

  /** Bounded housekeeping, called from the arbiter's sweep. */
  prune(now: number): number {
    let removed = 0;
    for (const [key, entry] of this.#recent) {
      if (now - entry.at > REQUEST_LIMITS.dedupeMs) {
        this.#recent.delete(key);
        removed += 1;
      }
    }
    return removed;
  }

  #remember(key: string, entry: { at: number; ref: string }): void {
    this.#recent.set(key, entry);
    if (this.#recent.size <= REQUEST_LIMITS.dedupeCap) return;
    // Map preserves insertion order, so the first key walked is the oldest. A spray
    // cannot grow this map past the cap.
    const oldest = this.#recent.keys().next();
    if (!oldest.done) this.#recent.delete(oldest.value);
  }
}

/** Exported for the test suite, which asserts the closed set matches the wire contract. */
export const REQUEST_PROFILES: readonly BuildProfile[] = BUILD_PROFILES;

/** Exported so a caller can classify an error code without duplicating the set. */
export function isApiErrorCode(value: string): value is ApiErrorCode {
  return ERROR_SET.has(value);
}
