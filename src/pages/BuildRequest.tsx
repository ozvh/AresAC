/**
 * Build request page.
 *
 * This is the only public surface on the deployment. Everything else — the ingest path,
 * the stream, the snapshot, the control plane — expects either a signed principal or an
 * operator, so this page is where a stranger with no credentials can start a
 * conversation, and it is built to survive being found by a script.
 *
 * WHAT THIS PAGE IS NOT ALLOWED TO DO.
 *
 *  - It cannot name the recipient. The destination address lives in the relay's own
 *    configuration on the server; the browser never learns it and could not change it
 *    if it did. A form that carries its destination in the payload is an open relay.
 *  - It cannot decide anything. Client-side bounds here exist to give a fast, honest
 *    answer about a malformed field; the authoritative bounds are in the server's
 *    intake policy, and the validator below is written to agree with them rather than
 *    to replace them.
 *  - It cannot report whether mail was actually delivered. Acknowledgement means the
 *    request cleared every gate and reached the relay. The relay's own verdict is
 *    sealed into the arbiter's ledger, where an operator can see it and a submitter
 *    cannot.
 *
 * The form does not navigate. `form-action 'none'` in the deployment's
 * Content-Security-Policy means a native submit is blocked outright, so the only way
 * this payload can leave the page is the same-origin fetch below. With JavaScript
 * broken, the form fails closed instead of leaking a submission to a URL an attacker
 * could have rewritten.
 */
import { useRef, useState, type FormEvent, type JSX, type ReactNode } from "react";
import {
  BUILD_PROFILES,
  REQUEST_LIMITS,
  type ApiError,
  type BuildProfile,
  type BuildRequestAck,
  type BuildRequestInput,
} from "@shared/protocol";

type Phase = "IDLE" | "SENDING" | "ACCEPTED" | "REFUSED";

/** Local mirror of the server's address rule. Kept deliberately loose; see server/requests.ts. */
const EMAIL_SHAPE = /^[A-Za-z0-9._%+-]+@[A-Za-z0-9-]+(\.[A-Za-z0-9-]+)+$/;

/**
 * A single form row. Labels are fixed-width so the input column cannot move when a
 * field gains a validation message.
 */
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

export default function BuildRequest(): JSX.Element {
  const [name, setName] = useState<string>("");
  const [email, setEmail] = useState<string>("");
  const [org, setOrg] = useState<string>("");
  const [profile, setProfile] = useState<BuildProfile>("RETAIL");
  const [note, setNote] = useState<string>("");
  const [trap, setTrap] = useState<string>("");
  const [phase, setPhase] = useState<Phase>("IDLE");
  const [reference, setReference] = useState<string>("");
  const [reason, setReason] = useState<string>("");

  // Dwell clock. Advisory: the server checks the value we send it, and it knows the
  // value is ours to forge. It exists to drop submissions from a run that never
  // rendered a page, nothing more.
  const openedAt = useRef<number>(Date.now());

  const nameOk = name.trim().length >= REQUEST_LIMITS.nameMin;
  const emailOk = EMAIL_SHAPE.test(email.trim()) && email.trim().length <= REQUEST_LIMITS.emailMax;
  const noteOk = note.trim().length >= REQUEST_LIMITS.noteMin;
  const complete = nameOk && emailOk && noteOk && phase !== "SENDING";

  async function submit(event: FormEvent<HTMLFormElement>): Promise<void> {
    event.preventDefault();
    if (phase === "SENDING") return;

    setPhase("SENDING");
    setReason("");

    const payload: BuildRequestInput = {
      nm: name.trim(),
      em: email.trim(),
      org: org.trim(),
      tgt: profile,
      msg: note.trim(),
      hp: trap,
      el: Date.now() - openedAt.current,
    };

    try {
      const res = await fetch("/v1/request", {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify(payload),
      });
      const body = (await res.json()) as BuildRequestAck | ApiError;

      if (res.status === 202 && "ok" in body && body.ok) {
        setReference(body.ref);
        setPhase("ACCEPTED");
        // Clear the requester's own words once they are accepted. The page has no
        // reason to keep them, and a form that leaves them on screen invites a
        // duplicate submission.
        setName("");
        setEmail("");
        setOrg("");
        setNote("");
        return;
      }

      // The arbiter's own words, unedited. Paraphrasing a refusal is how a refusal
      // becomes a mystery.
      setReason("msg" in body ? `${body.e} · ${body.msg}` : `HTTP ${res.status}`);
      setPhase("REFUSED");
    } catch {
      setReason("MALFORMED · transport failure, nothing was recorded");
      setPhase("REFUSED");
    }
  }

  return (
    <div className="flex min-h-screen flex-col bg-void text-fg">
      {/* ---------- header ---------- */}
      <header className="flex h-[30px] shrink-0 items-center justify-between gap-4 border-b border-line bg-panel px-2 text-[10px] uppercase tracking-[0.18em]">
        <span className="flex items-center gap-3">
          <span className="text-fg">ZEUS // BUILD REQUEST</span>
          <span className="text-dimmer">PUBLIC SURFACE · RATE-LIMITED · LEDGER-SEALED</span>
        </span>
        <a href="/" className="text-dim hover:text-fg">
          OPERATOR CONSOLE {"->"}
        </a>
      </header>

      <main className="mx-auto flex w-full max-w-[880px] flex-1 flex-col px-4 py-6">
        {/* ---------- statement ---------- */}
        <section className="flex flex-col gap-2 border-b border-line pb-4">
          <h1 className="text-[13px] uppercase tracking-[0.18em] text-fg">REQUEST A BUILD</h1>
          <p className="max-w-[70ch] text-[11px] leading-relaxed text-dim">
            Builds are issued by request rather than downloaded. Each request is relayed to the maintainer, who
            answers by reply. The channel you select determines what is prepared: a signed retail build is the
            supported release, a development build carries instrumentation that changes measured performance, a
            source distribution ships the engine without signing keys, and an evaluation build expires.
          </p>
          <p className="max-w-[70ch] text-[11px] leading-relaxed text-dimmer">
            This is the only unauthenticated surface on this deployment. Submissions are bounded in size and
            counted against a per-source and a process-wide velocity limit; a submission that clears every gate is
            sealed into the arbiter&apos;s hash-chained ledger. Nothing you type is rendered anywhere except the
            message the maintainer receives.
          </p>
        </section>

        {/* ---------- form ---------- */}
        <form onSubmit={(event) => void submit(event)} noValidate className="flex flex-col border-b border-line">
          <Row htmlFor="br-name" label="CALLSIGN" hint="how the maintainer should address you">
            <input
              id="br-name"
              type="text"
              value={name}
              maxLength={REQUEST_LIMITS.nameMax}
              autoComplete="off"
              spellCheck={false}
              aria-invalid={name.length > 0 && !nameOk}
              onChange={(event) => setName(event.currentTarget.value)}
              className="w-full max-w-[420px] text-[11px]"
            />
            {name.length > 0 && !nameOk ? (
              <span className="text-[10px] text-flagged">{`[!] AT LEAST ${REQUEST_LIMITS.nameMin} CHARACTERS`}</span>
            ) : null}
          </Row>

          <Row htmlFor="br-email" label="REPLY ADDRESS" hint="one mailbox that reaches you; used as reply-to only">
            <input
              id="br-email"
              type="email"
              value={email}
              maxLength={REQUEST_LIMITS.emailMax}
              autoComplete="off"
              spellCheck={false}
              aria-invalid={email.length > 0 && !emailOk}
              onChange={(event) => setEmail(event.currentTarget.value)}
              className="w-full max-w-[420px] text-[11px]"
            />
            {email.length > 0 && !emailOk ? (
              <span className="text-[10px] text-flagged">{"[!] THIS IS NOT A READABLE ADDRESS"}</span>
            ) : null}
          </Row>

          <Row htmlFor="br-org" label="ORGANISATION" hint="optional; leave empty if none applies">
            <input
              id="br-org"
              type="text"
              value={org}
              maxLength={REQUEST_LIMITS.orgMax}
              autoComplete="off"
              spellCheck={false}
              onChange={(event) => setOrg(event.currentTarget.value)}
              className="w-full max-w-[420px] text-[11px]"
            />
          </Row>

          <Row htmlFor="br-profile" label="BUILD CHANNEL" hint="closing this list is deliberate: it is written into a record">
            <select
              id="br-profile"
              value={profile}
              onChange={(event) => {
                const next = BUILD_PROFILES.find((candidate) => candidate === event.currentTarget.value);
                if (next !== undefined) setProfile(next);
              }}
              className="w-full max-w-[420px] text-[11px]"
            >
              {BUILD_PROFILES.map((candidate) => (
                <option key={candidate} value={candidate}>
                  {candidate}
                </option>
              ))}
            </select>
          </Row>

          <Row
            htmlFor="br-note"
            label="NOTE"
            hint={`what you intend to do with it · ${REQUEST_LIMITS.noteMin}–${REQUEST_LIMITS.noteMax} characters`}
          >
            <textarea
              id="br-note"
              value={note}
              maxLength={REQUEST_LIMITS.noteMax}
              rows={7}
              spellCheck={false}
              aria-invalid={note.length > 0 && !noteOk}
              onChange={(event) => setNote(event.currentTarget.value)}
              className="w-full resize-none text-[11px] leading-relaxed"
            />
            <span className="num text-[10px] text-dimmer">
              {`${String(note.trim().length).padStart(4, " ")} / ${REQUEST_LIMITS.noteMax}`}
            </span>
          </Row>

          {/* Honeypot. Removed from the tab order and from the accessibility tree; a
              person cannot reach it, a form-filling script will. Not display:none,
              because some scripts skip undisplayed fields. */}
          <div aria-hidden="true" className="absolute -left-[9999px] top-0 h-0 w-0 overflow-hidden">
            <label htmlFor="br-trap">leave this field empty</label>
            <input
              id="br-trap"
              type="text"
              value={trap}
              tabIndex={-1}
              autoComplete="off"
              onChange={(event) => setTrap(event.currentTarget.value)}
            />
          </div>

          <div className="flex items-center justify-between gap-4 py-4">
            <span className="text-[10px] uppercase tracking-[0.12em] text-dimmer">
              {phase === "SENDING" ? "TRANSMITTING" : "SUBMISSION IS BOUND TO ONE RECIPIENT SET SERVER-SIDE"}
            </span>
            <button
              type="submit"
              disabled={!complete}
              className="shrink-0 px-4 py-2 text-[10px] uppercase tracking-[0.18em]"
            >
              {phase === "SENDING" ? "[ SENDING ]" : "[ SEND REQUEST ]"}
            </button>
          </div>
        </form>

        {/* ---------- outcome ---------- */}
        <section className="flex flex-col gap-2 py-4" aria-live="polite">
          <span className="text-[10px] uppercase tracking-[0.18em] text-dimmer">OUTCOME</span>
          {phase === "IDLE" || phase === "SENDING" ? (
            <span className="text-[11px] text-dimmer">—</span>
          ) : phase === "ACCEPTED" ? (
            <>
              <span className="text-[11px] uppercase tracking-[0.12em] text-clean">
                {`[+] ACCEPTED · REFERENCE ${reference}`}
              </span>
              <p className="max-w-[70ch] text-[11px] leading-relaxed text-dim">
                The request cleared every gate and was handed to the relay, and a sealed record of that act is now in
                the arbiter&apos;s ledger. Quote the reference above if you follow up. A response arrives at the
                address you gave, as a reply to the message this form produced.
              </p>
            </>
          ) : (
            <>
              <span className="text-[11px] uppercase tracking-[0.12em] text-flagged">{"[x] REFUSED"}</span>
              <span className="num break-all text-[11px] text-dim">{reason}</span>
              <p className="max-w-[70ch] text-[11px] leading-relaxed text-dimmer">
                A refusal is either a field the arbiter will not accept or a velocity limit. Nothing was relayed and
                nothing was sealed. A rate refusal clears on its own; wait a minute and submit once rather than
                repeatedly, since each attempt spends budget.
              </p>
            </>
          )}
        </section>
      </main>

      <footer className="flex shrink-0 flex-col gap-1 border-t border-line bg-panel px-3 py-2 text-[10px] leading-relaxed text-dimmer">
        <span>
          Recorded per submission: the channel requested, a one-way digest of the reply address, a reference, and the
          relay&apos;s own verdict. The message body itself is not recorded in the ledger and is not rendered in the
          console.
        </span>
        <span>
          The recipient is fixed in server configuration and is never transmitted to this page, so no field here can
          redirect a submission.
        </span>
      </footer>
    </div>
  );
}
