/**
 * Subscriptions, renewal notices and cancellation.
 *
 * THREE COMMITMENTS, each expressed as something the code can be held to.
 *
 * 1. A REMINDER IS SENT BEFORE EVERY RENEWAL, EXACTLY ONCE PER PERIOD. `reminder_sent_for`
 *    stores the period end that was last warned about. A sweeper that merely compared
 *    dates would mail on every pass; a sweeper that watched only a boolean would warn
 *    once ever. Recording the period makes the guarantee "once per renewal" rather than
 *    "recently", which is the difference between a notice and a nuisance.
 *
 * 2. CANCELLING COSTS NO MORE THAN SIGNING UP. Signing up requires five fields and two
 *    consent boxes. Cancelling requires one field and one click, and the test suite
 *    asserts that inequality against the signup contract rather than trusting the copy on
 *    the page. Cancellation takes effect at the end of the paid period, so it never
 *    confiscates time already paid for, and it is immediate — no retention call, no
 *    cooling-off queue, no step that exists to slow it down.
 *
 * 3. NO PAYMENT PROCESSOR IS WIRED. There is no provider credential here, and inventing
 *    one would be worse than not having it. What exists is the authority model a
 *    processor would drive: plans with period lengths, an auto-renew flag, a cancellation
 *    state and an audit record for each transition. `docs/SECURITY.md` names what a real
 *    integration must add — webhook signature verification against the provider's key,
 *    idempotency keys on every mutation, and reconciliation between their state and ours.
 */
import { randomBytes } from "node:crypto";
import type { Plan, SubscriptionRow } from "./db.ts";
import { Store } from "./db.ts";
import { Mailer } from "./mailer.ts";

export type PlanSpec = {
  readonly plan: Plan;
  readonly label: string;
  readonly periodDays: number;
  /** Amount in minor units. Zero for evaluation, and stated as such in the notice. */
  readonly amountCents: number;
};

export const PLANS: Readonly<Record<Plan, PlanSpec>> = {
  EVALUATION: { plan: "EVALUATION", label: "evaluation", periodDays: 30, amountCents: 0 },
  RETAIL: { plan: "RETAIL", label: "retail", periodDays: 30, amountCents: 1_900 },
  SOURCE: { plan: "SOURCE", label: "source", periodDays: 90, amountCents: 4_900 },
};

const DAY_MS = 24 * 60 * 60 * 1_000;

/** Cancelling needs a target identifier and one explicit confirmation. That is all. */
export const CANCEL_FIELDS = ["subId", "confirm"] as const;

export type CancelInput = { readonly subId: string; readonly confirm: boolean };

export type SubResult<T> = { readonly ok: true; readonly value: T } | { readonly ok: false; readonly code: string; readonly msg: string; readonly status: number };

function fail(code: string, msg: string, status: number): SubResult<never> {
  return { ok: false, code, msg, status };
}

export function parseCancel(raw: string): { ok: true; input: CancelInput } | { ok: false; code: string; msg: string } {
  let parsed: unknown;
  try {
    parsed = JSON.parse(raw);
  } catch {
    return { ok: false, code: "MALFORMED", msg: "body is not JSON" };
  }
  if (typeof parsed !== "object" || parsed === null || Array.isArray(parsed)) {
    return { ok: false, code: "SCHEMA", msg: "body must be an object" };
  }
  const record = parsed as Record<string, unknown>;
  const keys = Object.keys(record);
  if (keys.length !== CANCEL_FIELDS.length) return { ok: false, code: "SCHEMA", msg: "unknown or missing fields" };
  for (const key of CANCEL_FIELDS) {
    if (!Object.hasOwn(record, key)) return { ok: false, code: "SCHEMA", msg: `missing field ${key}` };
  }
  const subId = record["subId"];
  const confirm = record["confirm"];
  if (typeof subId !== "string" || !/^[0-9a-f]{32}$/.test(subId)) {
    return { ok: false, code: "SCHEMA", msg: "subId is not a subscription identifier" };
  }
  if (confirm !== true) {
    // Explicit rather than a default. A cancellation that happens because a field was
    // omitted is not a cancellation the person intended.
    return { ok: false, code: "SCHEMA", msg: "confirm must be true" };
  }
  return { ok: true, input: { subId, confirm: true } };
}

export type ReminderOutcome = {
  readonly subscriptionId: string;
  readonly relay: string;
  readonly periodEnd: number;
};

export class Subscriptions {
  readonly #store: Store;
  readonly #mailer: Mailer;
  readonly #now: () => number;
  readonly #noticeDays: number;

  constructor(args: { readonly store: Store; readonly mailer: Mailer; readonly now: () => number; readonly noticeDays: number }) {
    this.#store = args.store;
    this.#mailer = args.mailer;
    this.#now = args.now;
    this.#noticeDays = args.noticeDays;
  }

  get noticeDays(): number {
    return this.#noticeDays;
  }

  createFor(userId: string, plan: Plan, autoRenew: boolean): SubscriptionRow {
    const now = this.#now();
    const spec = PLANS[plan];
    this.#store.insertSubscription({
      id: randomBytes(16).toString("hex"),
      userId,
      plan,
      now,
      periodEnd: now + spec.periodDays * DAY_MS,
      autoRenew,
    });
    const created = this.#store.activeSubscription(userId);
    if (created === null) throw new Error("subscription insert did not produce a row");
    return created;
  }

  /**
   * Cancel, scoped to the owning account.
   *
   * The ownership check is a query constraint, not a branch: `subscriptionFor` takes the
   * user id, so there is no code path here that could act on a subscription belonging to
   * someone else even if this method were later called from somewhere new.
   */
  cancel(userId: string, input: CancelInput, ipHash: string): SubResult<SubscriptionRow> {
    const now = this.#now();
    const existing = this.#store.subscriptionFor(input.subId, userId);
    if (existing === null) {
      this.#store.audit({
        ts: now,
        actorId: userId,
        actorRole: "CUSTOMER",
        action: "SUB.CANCEL",
        subjectId: input.subId,
        outcome: "REFUSED",
        detail: "no such subscription for this account",
        ipHash,
      });
      return fail("NOT_FOUND", "no such subscription", 404);
    }
    if (existing.status !== "ACTIVE") {
      return fail("NOT_ACTIVE", "that subscription is not active", 409);
    }

    this.#store.cancelSubscription(existing.id, now);
    this.#store.audit({
      ts: now,
      actorId: userId,
      actorRole: "CUSTOMER",
      action: "SUB.CANCEL",
      subjectId: existing.id,
      outcome: "OK",
      detail: `auto-renew off; service continues to ${new Date(existing.current_period_end).toISOString()}`,
      ipHash,
    });

    const updated = this.#store.subscriptionFor(existing.id, userId);
    if (updated === null) return fail("INTERNAL", "cancellation could not be read back", 500);
    return { ok: true, value: updated };
  }

  setAutoRenew(userId: string, subId: string, on: boolean, ipHash: string): SubResult<SubscriptionRow> {
    const now = this.#now();
    const existing = this.#store.subscriptionFor(subId, userId);
    if (existing === null) return fail("NOT_FOUND", "no such subscription", 404);
    this.#store.setAutoRenew(existing.id, on, now);
    this.#store.audit({
      ts: now,
      actorId: userId,
      actorRole: "CUSTOMER",
      action: "SUB.AUTORENEW",
      subjectId: existing.id,
      outcome: "OK",
      detail: on ? "auto-renew enabled" : "auto-renew disabled",
      ipHash,
    });
    const updated = this.#store.subscriptionFor(existing.id, userId);
    if (updated === null) return fail("INTERNAL", "update could not be read back", 500);
    return { ok: true, value: updated };
  }

  /**
   * Mail the accounts whose renewal is inside the notice window.
   *
   * The message is plain text, states the date and the amount, and says how to stop it in
   * one action. A notice that does not tell someone how to cancel is a notice that exists
   * to prevent cancellation.
   */
  async sendDueReminders(limit = 32): Promise<ReminderOutcome[]> {
    const now = this.#now();
    const due = this.#store.dueRenewalNotices(now, this.#noticeDays * DAY_MS, limit);
    const outcomes: ReminderOutcome[] = [];

    for (const subscription of due) {
      const user = this.#store.userById(subscription.user_id);
      if (user === null) continue;
      const spec = PLANS[subscription.plan];
      const when = new Date(subscription.current_period_end).toISOString().slice(0, 10);
      const amount = spec.amountCents === 0 ? "no charge" : `${(spec.amountCents / 100).toFixed(2)}`;

      const text = [
        "ARES subscription notice",
        "",
        `This is the notice that precedes a renewal.`,
        "",
        `account        ${user.email}`,
        `plan           ${spec.label}`,
        `renews on      ${when}`,
        `amount         ${amount}`,
        `auto-renew     ON`,
        "",
        "--- stopping it ---",
        "Sign in and open your account page. Cancelling is one action there and needs no",
        "reason, no call and no notice period. Auto-renewing can also be switched off on the",
        "same page; either way the term you have already paid for runs to its end.",
        "",
        `This notice is sent once per renewal, ${this.#noticeDays} days before the date above.`,
        "",
      ].join("\n");

      const outcome = await this.#mailer.deliver({
        to: user.email,
        from: this.#mailer.from,
        replyTo: null,
        subject: `[ARES] your ${spec.label} subscription renews on ${when}`,
        text,
      });

      // The marker moves only after the relay answered. A crash between the two would
      // re-send, which is the harmless direction of that failure: a duplicate notice
      // beats a renewal nobody was warned about.
      this.#store.markReminderSent(subscription.id, subscription.current_period_end);
      this.#store.audit({
        ts: now,
        actorId: null,
        actorRole: "SYSTEM",
        action: "SUB.RENEWAL_NOTICE",
        subjectId: subscription.id,
        outcome: outcome.relay === "FAILED" ? "REFUSED" : "OK",
        detail: `${outcome.relay} for period ending ${when}`,
        ipHash: "",
      });
      outcomes.push({ subscriptionId: subscription.id, relay: outcome.relay, periodEnd: subscription.current_period_end });
    }

    return outcomes;
  }

  /** Expire periods that have ended. Bounded housekeeping, called from the arbiter sweep. */
  sweep(): number {
    return this.#store.expireSubscriptions(this.#now());
  }
}
