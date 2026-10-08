/**
 * Build-request mail relay.
 *
 * The transport speaks one shape: a JSON POST to a provider's send endpoint with a
 * bearer key. That shape covers Resend, Postmark's `/email` resource and several
 * others, so the relay is a configuration rather than a vendor dependency and no
 * SDK is pulled into a process whose dependency surface is part of its threat model.
 *
 * TWO PROPERTIES MATTER MORE THAN DELIVERY.
 *
 * 1. A REQUEST IS NEVER LOST TO A CONFIGURATION ERROR. If no key is configured, if
 *    the provider refuses the message, or if the network is down, the message is
 *    appended to a spool file and the outcome is reported as SPOOLED rather than
 *    FAILED. Someone asking for a build has no way to know the relay was misconfigured,
 *    and silently dropping their request is the one failure this component cannot
 *    accept. The operator sees SPOOLED in the ledger; the requester sees nothing.
 *
 * 2. NO SECRET AND NO RECIPIENT ADDRESS ESCAPES IN A DIAGNOSTIC. The outcome detail
 *    carries a status code, never a response body and never the key. The spool is the
 *    only place requester data lands, it is created 0600, and it is never read back
 *    into a response.
 *
 * Header fields are single-lined before transmission. The body is passed as a JSON
 * string value, which is not itself a header-injection surface — but `reply_to` is
 * derived from a value a stranger typed, and a relay that happily accepts a CRLF in an
 * address field is a relay that can be made to emit mail to someone else.
 */
import { appendFile } from "node:fs/promises";
import path from "node:path";

export type RelayState = "DELIVERED" | "SPOOLED" | "FAILED";

export type MailOutcome = {
  readonly relay: RelayState;
  /** Non-identifying diagnostic: a status code or a fixed phrase. Never a body. */
  readonly detail: string;
};

export type MailMessage = {
  readonly to: string;
  readonly from: string;
  readonly replyTo: string | null;
  readonly subject: string;
  readonly text: string;
};

export type MailerConfig = {
  /** Bearer credential. Empty means spool-only operation. */
  readonly apiKey: string;
  readonly from: string;
  readonly recipient: string;
  readonly endpoint: string;
  readonly spoolPath: string;
  readonly timeoutMs: number;
};

/** Default recipient of every build request. Fixed here, never client-supplied. */
export const DEFAULT_RECIPIENT = "cagelove094@gmail.com";

/** Provider default sender. A verified domain is required to send from anything else. */
const DEFAULT_FROM = "ARES Arbiter <onboarding@resend.dev>";

const DEFAULT_ENDPOINT = "https://api.resend.com/emails";

const DEFAULT_SPOOL = ".ares-requests.log";

/** Hard ceilings on the transmitted message, independent of the intake bounds. */
const SUBJECT_MAX = 180;
const ADDRESS_MAX = 254;
const FROM_MAX = 200;
const TEXT_MAX = 20_000;

/**
 * Collapse a value to a single line and drop control characters.
 *
 * This is the defence for every field that becomes a mail header. A CRLF in a
 * header value is how a message becomes two messages.
 */
function singleLine(value: string, max: number): string {
  let out = "";
  for (const ch of value) {
    const code = ch.codePointAt(0) ?? 0;
    out += code < 0x20 || code === 0x7f ? " " : ch;
    if (out.length >= max) break;
  }
  return out.trim();
}

/**
 * Body sanitation. Newlines are structure in a plain-text message and survive;
 * every other control character becomes a space so a crafted note cannot rewrite
 * how the message reads as a whole.
 */
function bodyText(value: string, max: number): string {
  let out = "";
  for (const ch of value) {
    if (ch === "\n") {
      out += "\n";
      continue;
    }
    const code = ch.codePointAt(0) ?? 0;
    out += code < 0x20 || code === 0x7f ? " " : ch;
    if (out.length >= max) break;
  }
  return out.slice(0, max);
}

/**
 * Address mask for operator-facing output: first two cells, then the domain.
 * Enough to recognise an address you already know, not enough to harvest one.
 */
export function maskAddress(value: string): string {
  const at = value.lastIndexOf("@");
  if (at <= 0 || at === value.length - 1) return "—";
  const local = value.slice(0, at);
  const domain = value.slice(at + 1);
  const head = local.length <= 2 ? local : local.slice(0, 2);
  return `${head}${"*".repeat(Math.max(1, Math.min(10, local.length - head.length)))}@${domain}`;
}

function delay(ms: number): Promise<void> {
  return new Promise((resolve) => {
    setTimeout(resolve, ms);
  });
}

export class Mailer {
  readonly configured: boolean;
  readonly recipient: string;
  readonly from: string;
  readonly #apiKey: string;
  readonly #endpoint: string;
  readonly #spoolPath: string;
  readonly #timeoutMs: number;

  constructor(config: MailerConfig) {
    this.#apiKey = config.apiKey;
    this.#endpoint = config.endpoint;
    this.#spoolPath = config.spoolPath;
    this.#timeoutMs = config.timeoutMs;
    this.recipient = config.recipient;
    this.from = config.from;
    this.configured = config.apiKey.length > 0;
  }

  /**
   * Resolve a relay from the environment.
   *
   * `spoolPath` is resolved against the working directory because the whole point of
   * the spool is that an operator can find it without being told where it went.
   */
  static fromEnv(env: NodeJS.ProcessEnv): Mailer {
    return new Mailer({
      apiKey: (env["RESEND_API_KEY"] ?? "").trim(),
      from: (env["ARES_REQUEST_FROM"] ?? DEFAULT_FROM).trim(),
      recipient: (env["ARES_REQUEST_TO"] ?? DEFAULT_RECIPIENT).trim(),
      endpoint: (env["ARES_REQUEST_ENDPOINT"] ?? DEFAULT_ENDPOINT).trim(),
      spoolPath: path.resolve(process.cwd(), env["ARES_REQUEST_SPOOL"] ?? DEFAULT_SPOOL),
      timeoutMs: 8_000,
    });
  }

  /** Where a spooled message landed. Printed at boot so it is never a mystery file. */
  get spoolPath(): string {
    return this.#spoolPath;
  }

  get summary(): string {
    const target = maskAddress(this.recipient);
    return this.configured ? `${target} via relay` : `${target} via spool (no RESEND_API_KEY)`;
  }

  /**
   * Hand one message to the relay.
   *
   * One retry, and only for conditions that can plausibly clear on their own: a 5xx
   * or an unreachable host. A 4xx is a configuration answer and retrying it just
   * doubles the latency of a decision that has already been made.
   */
  async deliver(message: MailMessage): Promise<MailOutcome> {
    const payload: Record<string, string | readonly string[]> = {
      from: singleLine(message.from, FROM_MAX),
      to: [singleLine(message.to, ADDRESS_MAX)],
      subject: singleLine(message.subject, SUBJECT_MAX),
      text: bodyText(message.text, TEXT_MAX),
    };
    // Spread rather than assign: with exactOptionalPropertyTypes a present-but-null
    // reply_to is different from an absent one, and an absent one is the correct
    // statement when there is nobody to reply to.
    const withReply: Record<string, string | readonly string[]> =
      message.replyTo === null ? payload : { ...payload, reply_to: singleLine(message.replyTo, ADDRESS_MAX) };

    if (!this.configured) return this.#spool(message, "no relay credential configured");

    const body = JSON.stringify(withReply);
    let detail = "no attempt made";

    for (let attempt = 1; attempt <= 2; attempt += 1) {
      try {
        // eslint-disable-next-line no-await-in-loop -- Retry attempts, response draining, and backoff must finish in order to avoid duplicate mail.
        const res = await fetch(this.#endpoint, {
          method: "POST",
          headers: {
            authorization: `Bearer ${this.#apiKey}`,
            "content-type": "application/json",
            accept: "application/json",
          },
          body,
          signal: AbortSignal.timeout(this.#timeoutMs),
        });

        if (res.ok) {
          try {
            // Drain the response so the connection is not left half-read. The body
            // itself is discarded: it is provider output, and nothing in it is a fact
            // this system is willing to record.
            // eslint-disable-next-line no-await-in-loop -- Retry attempts, response draining, and backoff must finish in order to avoid duplicate mail.
            await res.text();
          } catch {
            // A failed drain does not change the verdict.
          }
          return { relay: "DELIVERED", detail: `relay accepted (http ${res.status})` };
        }

        detail = `relay refused with http ${res.status}`;
        if (res.status < 500) return this.#spool(message, detail);
      } catch {
        detail = "relay unreachable";
      }

      // eslint-disable-next-line no-await-in-loop -- Retry attempts, response draining, and backoff must finish in order to avoid duplicate mail.
      if (attempt === 1) await delay(400);
    }

    return this.#spool(message, detail);
  }

  /**
   * Append the message to the local spool.
   *
   * This is the last resort that makes the difference between "the operator can
   * recover the request" and "the request is gone". It is the only place a requester's
   * own words are written to disk, the file is created 0600, and nothing ever reads it
   * back into a response.
   */
  async #spool(message: MailMessage, detail: string): Promise<MailOutcome> {
    const record = {
      ts: Date.now(),
      to: message.to,
      from: message.from,
      replyTo: message.replyTo,
      subject: message.subject,
      text: message.text,
    };
    try {
      await appendFile(this.#spoolPath, `${JSON.stringify(record)}\n`, { encoding: "utf8", mode: 0o600 });
      return { relay: "SPOOLED", detail };
    } catch {
      // Spooling failed too. Report it as a failure rather than pretending; the
      // operator's ledger will carry the truth and the arbiter log will carry the
      // reason at boot.
      return { relay: "FAILED", detail: "spool write failed" };
    }
  }
}
