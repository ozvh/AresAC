/**
 * Privacy policy.
 *
 * This is written to describe what the code in this repository actually does, not what a
 * template says a service usually does. Every claim below is checkable against a file:
 * the retention window is `retentionDays` in `server/uploads.ts`, the password digest is
 * scrypt in `server/passwords.ts`, the session cookie is `HttpOnly` in `server/auth.ts`,
 * the audit log is append-only by database trigger in `server/db.ts`, and the mail relay
 * is the single third party and only when it is configured at all.
 *
 * Three of the disclosures here are unusual, and each is present because it was asked for
 * and is true:
 *
 *  - AI ASSISTANCE IS DISCLOSED. Parts of this system and parts of this document were
 *    drafted with the help of an AI coding tool, alongside the human work. That is stated
 *    plainly, together with what the AI does NOT do: it makes no decision about an
 *    account, a renewal or a ban.
 *  - THIRD PARTIES ARE NAMED, WITH THE CONDITION ATTACHED. There is exactly one, and it
 *    only sees anything when a relay credential has been configured. Saying "we may share
 *    data with partners" would be less true and less useful than naming the single case.
 *  - NO TESTIMONIALS ARE PUBLISHED, because none have been collected. A quote attributed
 *    to a person who never said it is the kind of thing this page exists to rule out.
 *
 * NOT LEGAL ADVICE. This is an engineering description written by the person who built the
 * system. A deployment that takes money or holds data about people in a regulated
 * jurisdiction needs it reviewed by someone qualified to do that, and needs the retention
 * figures and the third-party list re-checked whenever either changes.
 */
import type { JSX } from "react";
import { PLAN_LABEL } from "@shared/protocol";

/** Matches `PRIVACY_VERSION` in `server/auth.ts`. Consent rows cite this exact string. */
const VERSION = "2026-10-07";

/** Matches the default of `ARES_UPLOAD_RETENTION_DAYS` in `server/db.ts`. */
const UPLOAD_RETENTION_DAYS = 30;

/** Matches the default of `ARES_RENEWAL_NOTICE_DAYS`. */
const RENEWAL_NOTICE_DAYS = 14;

/**
 * Long disclosures are built as constants rather than inline template literals.
 *
 * Interpolating inside a JSX attribute puts a template literal inside an expression
 * container, and the parser then has to hold three nested contexts at once. Precomputing
 * the string keeps the attribute a single identifier, which is easier to read and removes a
 * class of syntax error entirely.
 */
const UPLOAD_RETENTION_TEXT = `Deleted automatically ${UPLOAD_RETENTION_DAYS} days after upload by a retention sweep that removes the file first and then marks the record. After that the bytes are gone from this deployment. Refused uploads are recorded but never written to disk.`;

const RENEWAL_NOTICE_TEXT = `A notice is emailed ${RENEWAL_NOTICE_DAYS} days before every renewal date, once per period, to the address on the account. It states the plan, the date, the amount, and how to stop it. The once-per-period guarantee is stored as the period that was warned about, not as a flag, so a notice cannot be sent twice for one renewal or skipped for the next.`;

const PLAN_LIST_TEXT = Object.keys(PLAN_LABEL).join(" · ");

function Section({ title, meta, children }: { title: string; meta: string; children: JSX.Element | JSX.Element[] }): JSX.Element {
  return (
    <section className="flex flex-col border-b border-line">
      <header className="flex h-[22px] shrink-0 items-center justify-between border-b border-line bg-panel px-2 text-[10px] uppercase tracking-[0.18em]">
        <span className="text-fg">{title}</span>
        <span className="text-dimmer">{meta}</span>
      </header>
      <div className="flex flex-col gap-2 px-2 py-3">{children}</div>
    </section>
  );
}

function Row({ term, detail }: { term: string; detail: string }): JSX.Element {
  return (
    <div className="grid grid-cols-[190px_minmax(0,1fr)] gap-x-4 border-b border-line py-1.5 text-[11px] leading-relaxed">
      <span className="text-dimmer uppercase tracking-[0.08em]">{term}</span>
      <span className="text-dim">{detail}</span>
    </div>
  );
}

export default function Privacy(): JSX.Element {
  return (
    <div className="flex min-h-screen flex-col bg-void text-fg">
      <header className="flex h-[30px] shrink-0 items-center justify-between gap-4 border-b border-line bg-panel px-2 text-[10px] uppercase tracking-[0.18em]">
        <span className="flex items-center gap-3">
          <span className="text-fg">ARES // PRIVACY POLICY</span>
          <span className="num text-dimmer">{`VERSION ${VERSION}`}</span>
        </span>
        <span className="flex items-center gap-3">
          <a href="/signup" className="text-dim hover:text-fg">
            CREATE AN ACCOUNT
          </a>
          <a href="/login" className="text-dim hover:text-fg">
            SIGN IN
          </a>
          <a href="/" className="text-dim hover:text-fg">
            {"<-"} HOME
          </a>
        </span>
      </header>

      <main className="mx-auto flex w-full max-w-[900px] flex-1 flex-col">
        <div className="flex flex-col gap-2 border-b border-line px-2 py-4">
          <h1 className="text-[13px] uppercase tracking-[0.18em] text-fg">WHAT THIS SERVICE DOES WITH YOUR DATA</h1>
          <p className="max-w-[82ch] text-[11px] leading-relaxed text-dim">
            This page describes the data this deployment collects, why it holds it, how long it keeps it, who else
            can see it, and how to make it stop. It describes the code that runs here rather than a generic service,
            so a claim below should be traceable to a specific behaviour. Where something is conditional, the
            condition is stated instead of being left out.
          </p>
          <p className="max-w-[82ch] text-[11px] leading-relaxed text-dimmer">
            Withdrawing consent, requesting deletion, or cancelling a subscription all take one action and no
            negotiation. Cancelling is deliberately shorter than signing up: sign-up asks for an address, a name, a
            password and two consent decisions, and cancelling asks for one confirmation.
          </p>
        </div>

        <Section title="WHAT IS COLLECTED" meta="ACCOUNT AND AUDIT DATA">
          <Row term="address" detail="Your email address, lower-cased for uniqueness. Used to sign you in and to send renewal notices. Never displayed to another customer." />
          <Row term="display name" detail="The name you type at sign-up. Shown to you and to an administrator." />
          <Row term="password" detail="Never stored, and never transmitted a second time. Only a memory-hard scrypt digest is stored, with a per-account salt and the cost parameters recorded in the digest itself. Nobody at this service can read your password, and it is not recoverable — a reset replaces it." />
          <Row term="session" detail="An opaque random identifier in a cookie your browser sends back. The server keeps a digest of it, not the value, so a copy of the database cannot be used to impersonate you. The cookie is HttpOnly, SameSite=Strict, and never readable by page script." />
          <Row term="sign-in metadata" detail="The time of each sign-in, and a one-way digest of the source address and the browser user agent. The raw address is not stored and is not written to any log. Digests exist so that repeated failures and suspicious patterns can be recognised without keeping a record of who connected from where." />
          <Row term="audit records" detail="Every sign-up, sign-in, refused sign-in, consent, password change, cancellation and administrative action. The account behind it, the outcome, and the time. Append-only, enforced by database triggers. This is the record that makes an administrative action accountable, so it is retained rather than pruned." />
          <Row term="consents" detail="Which policy version you accepted, when, and whether it has since been withdrawn. Consent is recorded at the moment of sign-up, because that moment cannot be reconstructed afterwards." />
          <Row term="renewal state" detail="Plan, period end, and whether auto-renew is on. There is no card number and no payment credential stored here: no card processor is connected to this deployment." />
          <Row term="uploaded artefacts" detail="If you attach a file, its contents, its size, a SHA-256 digest, and the name you gave it. Files are stored outside every web root under a random name with no extension, and nothing serves them back." />
          <Row term="build requests" detail="The callsign, address, organisation, requested channel and note you submit on the request form. The audit ledger records only the channel, a reference, and a one-way digest of your address — never the note, and never the address itself." />
          <Row term="engine telemetry" detail="The anti-cheat engine stores suspicion against a subject digest, never against an account. A subject digest is derived from a game account identity and is not linked to the account you sign in with on this site." />
        </Section>

        <Section title="WHAT IS NOT COLLECTED" meta="ABSENCES ARE ALSO A CLAIM">
          <Row term="no analytics" detail="No analytics product, no session recording, no heat maps, no advertising identifier, and no third-party script of any kind. The pages load exactly one origin." />
          <Row term="no remote fonts" detail="The typeface is resolved from your own operating system. Nothing is fetched from a font host, which is why there is no third-party origin in the page at all." />
          <Row term="no device fingerprinting" detail="Nothing is read from your hardware, canvas, audio stack or installed fonts in order to identify you across visits." />
          <Row term="no tracking pixels" detail="Renewal notices and build-request replies are plain text. There is no open-tracking pixel and no rewritten link in either of them." />
          <Row term="no sale of data" detail="Nothing collected here is sold, rented or exchanged. The only third party that can receive anything is named in the next section, and it receives one message only when a relay credential has been configured." />
        </Section>

        <Section title="RETENTION" meta="HOW LONG, AND WHY">
          <Row term="uploaded artefacts" detail={UPLOAD_RETENTION_TEXT} />
          <Row term="sessions" detail="A session ends after 7 days at the latest, whether or not it is used, and ends immediately when you sign out, when your password changes, or when an administrator suspends the account. Expired and revoked rows are pruned by the same sweep." />
          <Row term="build requests" detail="The message is held by the relay and in the local spool so it can be answered. The spool is a local file readable only by the process owner. Ask for it to be removed and it is removed." />
          <Row term="account data" detail="Kept for as long as the account exists. Deleting the account removes the address, the display name, the password digest, the sessions, the review uploads and the consents; the audit records survive in a form that no longer names you, because deleting the record of an administrative action is what would make such an action concealable." />
          <Row term="engine telemetry" detail="Bounded by design: a fixed sample window per subject, a fixed subject ceiling, and a twelve-hour retention window. Evidence older than the window cannot corroborate current evidence." />
        </Section>

        <Section title="THIRD PARTIES" meta="ONE, AND CONDITIONALLY">
          <Row term="mail relay" detail="Transactional email — account notices, renewal notices and build-request delivery — is handed to Resend when the deployment has configured an API key, because a server cannot deliver mail to a mailbox provider on its own. Resend receives the recipient address, the subject and the body of that one message." />
          <Row term="when it is not configured" detail="If no relay credential is set, nothing leaves this deployment at all: the message is appended to a local spool file on this machine, the operator is shown that it was spooled rather than delivered, and no third party receives anything. The interface states which of the two modes is active." />
          <Row term="hosting" detail="This deployment runs where it is hosted. The host necessarily sees network-level metadata — connections, timing, volume — as any host does. It is not given account data by this application." />
          <Row term="everything else" detail="There is no other recipient. No marketing platform, no CRM, no data broker, no analytics vendor, and no payment processor is connected to this system." />
        </Section>

        <Section title="SUBSCRIPTIONS AND NOTICES" meta="BEFORE MONEY MOVES">
          <Row term="notice before renewal" detail={RENEWAL_NOTICE_TEXT} />
          <Row term="renewal email is not marketing" detail="Renewal notices are sent to every auto-renewing account regardless of any marketing preference, because a notice that depends on an optional consent is not a notice." />
          <Row term="cancelling" detail="One confirmation, one action. No retention call, no reason field, no notice period, no cooling-off queue, and no step that exists to slow you down. Auto-renew switches off immediately and the period you have already paid for runs to its end." />
          <Row term="no card on file here" detail="No payment processor is integrated into this deployment. Should one be added, this policy must be updated before it is, because a processor becomes a second third party with its own retention." />
          <Row term="plans" detail={PLAN_LIST_TEXT} />
        </Section>

        <Section title="AI ASSISTANCE" meta="DISCLOSED">
          <p className="max-w-[82ch] text-[11px] leading-relaxed text-dim">
            AI assistance was used alongside the human work on this system. Parts of the implementation, and parts of
            this document, were drafted with the help of an AI coding tool, working from direction set and reviewed by
            the person who is responsible for the result. That assistance sat beside the engineering rather than
            replacing it, and it is disclosed here rather than left for someone to discover.
          </p>
          <p className="max-w-[82ch] text-[11px] leading-relaxed text-dim">
            What that tool does not do: it holds no account, has no access to this deployment, and makes no decision
            about anybody. It does not decide a ban, a renewal, a cancellation or a refund. Every decision this system
            records is made by code a person reviewed and by an operator who answers for it, and the audit trail names
            that operator.
          </p>
        </Section>

        <Section title="SECURITY MEASURES THAT AFFECT YOU" meta="WHAT PROTECTS THE DATA ABOVE">
          <Row term="passwords" detail="Stored as memory-hard scrypt digests with a per-account salt. Comparison is timing-safe, and an unknown address costs the same work as a known one so the sign-in response cannot be timed to discover who has an account." />
          <Row term="sessions" detail="Held server-side. The value in the cookie is meaningless on its own, changing a password ends every other session immediately, and an administrator suspending an account ends its sessions in the same transaction as the suspension." />
          <Row term="uploads" detail="Accepted only for a short list of inert formats, verified against the file's own leading bytes rather than its name. Archives, executables and whole formats that are themselves active content — SVG and HTML — are refused outright, and a file whose contents disagree with its extension is refused with it. A text file whose contents carry active markup is quarantined: the record is kept for the operator, the bytes are never written to disk, and the verdict says which of the three happened." />
          <Row term="input handling" detail="Every field is validated on the server against a closed set of expected keys and bounds. All database access uses bound parameters, so no value is ever assembled into a query." />
          <Row term="audit trail" detail="Every change of authority is sealed into a hash-chained, append-only log enforced by database triggers. A retroactive edit to any record is detectable, which is what makes the trail worth keeping." />
        </Section>

        <Section title="WHAT WE DO NOT DO" meta="COMMITMENTS WITHOUT A QUALIFIER">
          <Row term="no fake testimonials" detail="No customer quote is published anywhere on this site, because none has been collected or verified. Inventing one, or attributing words to someone who did not say them, would be a false statement about a person and is not done here." />
          <Row term="no pre-ticked boxes" detail="Marketing consent is off by default and is not bundled with the consents you have to accept. Withdrawing it is a single action and does not affect whether you can keep using the service." />
          <Row term="no dark patterns" detail="Cancelling is shorter than signing up, notice windows are stated in advance, and no step in any flow exists to obstruct it." />
          <Row term="no silent changes" detail="A new version of this policy is a new version number, and consent records name the version that was accepted. A material change requires accepting it again rather than being assumed to have accepted it." />
        </Section>

        <Section title="YOUR CONTROLS" meta="ONE ACTION EACH">
          <Row term="stop renewing" detail="The account page, one button. Takes effect immediately." />
          <Row term="turn off email" detail="Marketing consent can be withdrawn on the account page. Renewal notices will still be sent while a subscription auto-renews, because they are the notice that money is about to move." />
          <Row term="delete your account" detail="Requested by reply to any notice, or from the request form. Account data, sessions, review uploads and consents are removed; audit records are retained in a form that no longer names you." />
          <Row term="get a copy" detail="A copy of the account data held here is provided on request." />
          <Row term="ask a question" detail="The build-request form reaches the operator directly and is the supported contact route." />
        </Section>

        <Section title="SCOPE OF THIS DOCUMENT" meta="WHAT IT IS NOT">
          <Row term="not legal advice" detail="This is an engineering description of a specific deployment, written by the engineer responsible for it. It is not a substitute for review by someone qualified to advise on the laws that apply where you live." />
          <Row term="changes" detail="When the behaviour described here changes, this page and its version number change with it, and the consent on an existing account is re-requested rather than assumed." />
        </Section>

        <div className="flex flex-col gap-2 px-2 py-4 text-[11px] leading-relaxed text-dimmer">
          <span className="num">{`POLICY VERSION ${VERSION}`}</span>
          <span>
            Retention figures on this page are the configured values of this deployment: uploads {UPLOAD_RETENTION_DAYS}{" "}
            days, renewal notices {RENEWAL_NOTICE_DAYS} days before the period end. An operator who changes either
            setting must change this page in the same commit, which is why both are stated as numbers rather than as
            phrases like &quot;a reasonable period&quot;.
          </span>
        </div>
      </main>

      <footer className="flex shrink-0 flex-col gap-1 border-t border-line bg-panel px-3 py-2 text-[10px] leading-relaxed text-dimmer">
        <span>
          No testimonial, review, rating or customer quotation appears anywhere on this site. The absence is
          deliberate: none has been collected, and a fabricated one would be a false claim about a real person.
        </span>
        <span>
          No analytics, advertising or tracking service is embedded in these pages. This document is the complete list
          of recipients.
        </span>
      </footer>
    </div>
  );
}
