/**
 * Customer sign-up.
 *
 * WHAT THIS PAGE IS AND IS NOT ALLOWED TO DO.
 *
 * It is a form that collects four fields and three consent decisions, and it decides
 * nothing. Every rule it enforces locally — the address shape, the password floor, the
 * required consents — is a courtesy that saves a round trip, and each one mirrors a rule the
 * server enforces again for itself. The server is the authority for all of them; this page
 * exists to give an honest answer fast, not to be trusted.
 *
 * It cannot create an account with more authority than a customer. `role` is not a field
 * here, it is not in the payload `src/lib/account.ts` sends, and the server would ignore it
 * if it were present. The admin surface is reached by an existing administrator granting
 * the role, never by a request that asks for it.
 *
 * It does not navigate on success. Signing in is an act a person should see happen, and a
 * page that redirects itself is a page that can be made to redirect somewhere else by a
 * change nobody read carefully. Success is stated, and the next step is a link.
 *
 * CONSENT IS EXPLICIT, SEPARATE AND NOT PRE-TICKED. The privacy policy and the terms are
 * two independent decisions recorded under their own policy version, and the submit button
 * stays disabled until both are made. Marketing email is a third decision that defaults to
 * off — a pre-ticked marketing box is a dark pattern, and it also makes the other two
 * consents worthless, because a consent that is assumed has not been given.
 */
import { useState, type FormEvent, type JSX, type ReactNode } from "react";
import { signup, type Outcome } from "@/lib/account";
import type { AccountUser } from "@shared/protocol";

type Phase = "IDLE" | "SENDING" | "ACCEPTED" | "REFUSED";

/**
 * Local mirrors of the server's policy, kept deliberately in one place with a comment
 * naming the authority. `server/passwords.ts` is the source of both numbers; it cannot be
 * imported here because it reads `node:crypto`, and a server module in the client bundle is
 * a build failure at best and a leaked assumption at worst.
 */
const PASSWORD_FLOOR = 12;
const PASSWORD_CEILING = 200;
const NAME_CEILING = 80;
const EMAIL_CEILING = 254;

/** Same shape the build-request page uses; the server validates again with its own copy. */
const EMAIL_SHAPE = /^[A-Za-z0-9._%+-]+@[A-Za-z0-9-]+(\.[A-Za-z0-9-]+)+$/;

/** A form row. The label column is fixed so a validation message cannot move the inputs. */
function Row({
  htmlFor,
  label,
  hint,
  children,
}: {
  htmlFor: string;
  label: string;
  hint: string;
  children: ReactNode;
}): JSX.Element {
  return (
    <div className="grid grid-cols-[188px_minmax(0,1fr)] items-start gap-x-4 border-b border-line py-3">
      <div className="flex flex-col gap-1">
        <label htmlFor={htmlFor} className="text-[10px] uppercase tracking-[0.18em] text-fg">
          {label}
        </label>
        <span className="text-[10px] leading-snug text-dimmer">{hint}</span>
      </div>
      <div className="flex flex-col gap-1">{children}</div>
    </div>
  );
}

/** One consent decision. A checkbox, its own sentence, and nothing pre-ticked. */
function Consent({
  id,
  checked,
  onChange,
  children,
}: {
  id: string;
  checked: boolean;
  onChange: (next: boolean) => void;
  children: ReactNode;
}): JSX.Element {
  return (
    <div className="flex items-start gap-2 border-b border-line py-2">
      <input
        id={id}
        type="checkbox"
        checked={checked}
        onChange={(event) => onChange(event.currentTarget.checked)}
        className="mt-[2px] size-[12px] shrink-0"
      />
      <label htmlFor={id} className="text-[11px] leading-relaxed text-dim">
        {children}
      </label>
    </div>
  );
}

export default function Signup(): JSX.Element {
  const [email, setEmail] = useState<string>("");
  const [displayName, setDisplayName] = useState<string>("");
  const [password, setPassword] = useState<string>("");
  const [confirm, setConfirm] = useState<string>("");
  const [acceptPrivacy, setAcceptPrivacy] = useState<boolean>(false);
  const [acceptTerms, setAcceptTerms] = useState<boolean>(false);
  // Unticked, and it stays unticked unless a person ticks it.
  const [acceptMarketing, setAcceptMarketing] = useState<boolean>(false);
  const [phase, setPhase] = useState<Phase>("IDLE");
  const [reason, setReason] = useState<string>("");
  const [createdEmail, setCreatedEmail] = useState<string>("");

  const emailOk = EMAIL_SHAPE.test(email.trim()) && email.trim().length <= EMAIL_CEILING;
  const nameOk = displayName.trim().length >= 1 && displayName.trim().length <= NAME_CEILING;
  const passwordOk = password.length >= PASSWORD_FLOOR && password.length <= PASSWORD_CEILING;
  const confirmOk = confirm.length > 0 && confirm === password;
  const consentOk = acceptPrivacy && acceptTerms;
  const complete = emailOk && nameOk && passwordOk && confirmOk && consentOk && phase !== "SENDING";

  async function submit(event: FormEvent<HTMLFormElement>): Promise<void> {
    // A native submit would be blocked by `form-action 'none'`, so the browser would
    // appear to do nothing. The payload leaves this page through the same-origin call
    // below or it does not leave at all.
    event.preventDefault();
    if (phase === "SENDING") return;

    setPhase("SENDING");
    setReason("");

    const result: Outcome<AccountUser> = await signup({
      email: email.trim(),
      displayName: displayName.trim(),
      password,
      acceptPrivacy,
      acceptTerms,
      acceptMarketing,
    });

    if (!result.ok) {
      // The server's own sentence, unedited. Rewriting a refusal is how a refusal becomes
      // a mystery, and a vague message here would also obscure the one failure a person
      // can act on.
      setReason(result.reason);
      setPhase("REFUSED");
      return;
    }

    setCreatedEmail(result.value.email);
    setPhase("ACCEPTED");
    // The password and its confirmation are dropped from component state the moment the
    // account exists. There is no reason for either to stay in memory on this page.
    setPassword("");
    setConfirm("");
  }

  const pwCounter = `${String(password.length).padStart(4, " ")} / ${PASSWORD_CEILING}`;

  return (
    <div className="flex min-h-screen flex-col bg-void text-fg">
      <header className="flex h-[30px] shrink-0 items-center justify-between gap-4 border-b border-line bg-panel px-2 text-[10px] uppercase tracking-[0.18em]">
        <span className="flex items-center gap-3">
          <span className="text-fg">ARES // CREATE ACCOUNT</span>
          <span className="text-dimmer">CUSTOMER · HASHED · SERVER-SIDE SESSION</span>
        </span>
        <span className="flex shrink-0 items-baseline gap-3">
          <a href="/login" className="text-dim hover:text-fg">
            SIGN IN {"->"}
          </a>
          <a href="/" className="text-dimmer hover:text-fg">
            CONSOLE {"->"}
          </a>
        </span>
      </header>

      <main className="mx-auto flex w-full max-w-[880px] flex-1 flex-col px-4 py-6">
        <section className="flex flex-col gap-2 border-b border-line pb-4">
          <h1 className="text-[13px] uppercase tracking-[0.18em] text-fg">CREATE A CUSTOMER ACCOUNT</h1>
          <p className="max-w-[70ch] text-[11px] leading-relaxed text-dim">
            An account holds your build requests, your subscription and any artefact you send for inspection. It
            grants no operator authority: the console, the conviction state machine and the control plane are
            unreachable from a customer session, and the role on a new account is fixed at creation.
          </p>
          <p className="max-w-[70ch] text-[11px] leading-relaxed text-dimmer">
            Passwords are hashed with scrypt and a per-account salt before they touch disk, and the readable value is
            never stored, logged or transmitted again after this form. The session that results is a server-side
            record identified by an <span className="text-fg">HttpOnly</span> cookie that this page&apos;s scripts
            cannot read; no authentication token is placed in browser storage.
          </p>
        </section>

        {phase === "ACCEPTED" ? (
          <section className="flex flex-col gap-3 py-6" aria-live="polite">
            <span className="text-[11px] uppercase tracking-[0.12em] text-clean">{"[+] ACCOUNT CREATED"}</span>
            <span className="num break-all text-[11px] text-dim">{createdEmail}</span>
            <p className="max-w-[70ch] text-[11px] leading-relaxed text-dim">
              The account exists, the two required consents were recorded against the current policy versions, and a
              session is open on this device. Nothing was sent to you: there is no confirmation step, so an address
              that cannot receive mail has not blocked your account.
            </p>
            <p className="max-w-[70ch] text-[11px] leading-relaxed text-dimmer">
              Your account page shows the consents recorded against your account, your subscription and its renewal
              date, and the retention window that applies to anything you upload. Cancelling a subscription is a
              single action there, and it needs no reason and no waiting period.
            </p>
            <span className="pt-1">
              <a href="/account" className="text-[10px] uppercase tracking-[0.18em] text-fg hover:text-dim">
                CONTINUE TO YOUR ACCOUNT {"->"}
              </a>
            </span>
          </section>
        ) : (
          <form onSubmit={(event) => void submit(event)} noValidate className="flex flex-col border-b border-line">
            <Row htmlFor="su-email" label="EMAIL ADDRESS" hint="the account identifier; compared without regard to case">
              <input
                id="su-email"
                type="email"
                value={email}
                maxLength={EMAIL_CEILING}
                autoComplete="username"
                spellCheck={false}
                aria-invalid={email.length > 0 && !emailOk}
                onChange={(event) => setEmail(event.currentTarget.value)}
                className="w-full max-w-[420px] text-[11px]"
              />
              {email.length > 0 && !emailOk ? (
                <span className="text-[10px] text-flagged">{"[!] THIS IS NOT A READABLE ADDRESS"}</span>
              ) : null}
            </Row>

            <Row htmlFor="su-name" label="DISPLAY NAME" hint="how the maintainer addresses you; not unique">
              <input
                id="su-name"
                type="text"
                value={displayName}
                maxLength={NAME_CEILING}
                autoComplete="nickname"
                spellCheck={false}
                aria-invalid={displayName.length > 0 && !nameOk}
                onChange={(event) => setDisplayName(event.currentTarget.value)}
                className="w-full max-w-[420px] text-[11px]"
              />
              {displayName.length > 0 && !nameOk ? (
                <span className="text-[10px] text-flagged">{"[!] A DISPLAY NAME OF 1 TO 80 CHARACTERS IS REQUIRED"}</span>
              ) : null}
            </Row>

            <Row
              htmlFor="su-password"
              label="PASSWORD"
              hint={`at least ${PASSWORD_FLOOR} characters; length is the only rule that helps, so mixed case and symbols are not required`}
            >
              <input
                id="su-password"
                type="password"
                value={password}
                maxLength={PASSWORD_CEILING}
                autoComplete="new-password"
                spellCheck={false}
                aria-invalid={password.length > 0 && !passwordOk}
                onChange={(event) => setPassword(event.currentTarget.value)}
                className="w-full max-w-[420px] text-[11px]"
              />
              <span className="num text-[10px] text-dimmer">{pwCounter}</span>
              {password.length > 0 && !passwordOk ? (
                <span className="text-[10px] text-flagged">{`[!] AT LEAST ${PASSWORD_FLOOR} CHARACTERS`}</span>
              ) : null}
            </Row>

            <Row htmlFor="su-confirm" label="CONFIRM PASSWORD" hint="typed twice so a typo cannot lock you out immediately">
              <input
                id="su-confirm"
                type="password"
                value={confirm}
                maxLength={PASSWORD_CEILING}
                autoComplete="new-password"
                spellCheck={false}
                aria-invalid={confirm.length > 0 && !confirmOk}
                onChange={(event) => setConfirm(event.currentTarget.value)}
                className="w-full max-w-[420px] text-[11px]"
              />
              {confirm.length > 0 && !confirmOk ? (
                <span className="text-[10px] text-flagged">{"[!] THE TWO ENTRIES DO NOT MATCH"}</span>
              ) : null}
            </Row>

            <section className="flex flex-col pt-4">
              <span className="text-[10px] uppercase tracking-[0.18em] text-dimmer">
                CONSENT · TWO REQUIRED, ONE OPTIONAL
              </span>

              <Consent id="su-privacy" checked={acceptPrivacy} onChange={setAcceptPrivacy}>
                I have read the{" "}
                <a href="/privacy" className="text-fg underline hover:text-dim">
                  privacy policy
                </a>
                {" "}and accept it: it states what this service collects, how long uploads are retained, which third
                parties receive data, and that automated assistance was used in building it.
              </Consent>

              <Consent id="su-terms" checked={acceptTerms} onChange={setAcceptTerms}>
                I accept the terms of service, including that an account is for one person, that abuse ends it, and
                that cancelling a subscription takes one action and ends it at the close of the paid period.
              </Consent>

              <Consent id="su-marketing" checked={acceptMarketing} onChange={setAcceptMarketing}>
                Also send occasional product notices. Not ticked by default and entirely optional. Renewal notices are
                sent regardless of this box, because a warning that a subscription is about to renew is a notice about
                your own account rather than marketing.
              </Consent>

              <p className="pt-2 text-[10px] leading-relaxed text-dimmer">
                Both required boxes are your decision and are recorded separately against the policy versions in force
                today. Marketing consent is recorded only if you tick it, and it can be withdrawn from your account
                page without affecting anything else.
              </p>
            </section>

            <div className="flex items-center justify-between gap-4 py-4">
              <span className="text-[10px] uppercase tracking-[0.12em] text-dimmer">
                {phase === "SENDING"
                  ? "TRANSMITTING"
                  : consentOk
                    ? "REQUIRED CONSENTS GIVEN"
                    : "BOTH REQUIRED CONSENTS ARE NEEDED TO CONTINUE"}
              </span>
              <button
                type="submit"
                disabled={!complete}
                className="shrink-0 px-4 py-2 text-[10px] uppercase tracking-[0.18em]"
              >
                {phase === "SENDING" ? "[ CREATING ]" : "[ CREATE ACCOUNT ]"}
              </button>
            </div>
          </form>
        )}

        <section className="flex flex-col gap-2 py-4" aria-live="polite">
          <span className="text-[10px] uppercase tracking-[0.18em] text-dimmer">OUTCOME</span>
          {phase === "REFUSED" ? (
            <>
              <span className="text-[11px] uppercase tracking-[0.12em] text-flagged">
                {`[x] ${reason}`}
              </span>
              <p className="max-w-[70ch] text-[11px] leading-relaxed text-dimmer">
                A refusal is a field the server will not accept, a policy floor, or a velocity limit on this source.
                An address that is already registered is refused in the same words as any other failure, so this
                message cannot be used to discover whether an account exists. If the address is yours, sign in
                instead.
              </p>
            </>
          ) : (
            <span className="text-[11px] text-dimmer">
              {phase === "ACCEPTED" ? "[+] COMPLETE" : "—"}
            </span>
          )}
        </section>
      </main>

      <footer className="flex shrink-0 flex-col gap-1 border-t border-line bg-panel px-3 py-2 text-[10px] leading-relaxed text-dimmer">
        <span>
          Recorded at creation: the address, the display name, a scrypt digest of the password, the two required
          consents with their policy versions, and whether marketing consent was given. The readable password is not
          among them and cannot be recovered from what is stored.
        </span>
        <span>
          Failed attempts are counted against this source and each account is briefly locked after a run of them, so a
          repeated failure here is a limit rather than a broken form.
        </span>
      </footer>
    </div>
  );
}
