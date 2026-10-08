/**
 * Sign-in page.
 *
 * ONE PLACE, TWO AUTHORITIES. Customers and administrators sign in through the same form
 * and the same session mechanism, because a separate admin login would be a second
 * authentication path to keep correct — and the second one is always the weaker one.
 * What differs is only where the server sends you afterwards, and that decision is read
 * from the answer the server gave, never inferred here.
 *
 * THE PAGE DECIDES NOTHING. It does not decide whether the credentials were good, and it
 * does not decide who the account is. It renders the server's own refusal word for word,
 * and it reads the role from the response rather than from anything it holds. A page that
 * decided its own authority would be a page an attacker could edit.
 *
 * FAILURES ARE UNIFORM ON PURPOSE. An unknown address, a wrong password, a suspended
 * account and a locked one all produce one identical answer, and the server spends the
 * same password-hashing work on all four so the timing does not answer the question the
 * body refuses to. The note under a refusal says so, because an operator who does not know
 * that will file the uniformity as a bug and "fix" it into an enumeration oracle.
 *
 * The form does not navigate natively: `form-action 'none'` in the deployment's
 * Content-Security-Policy blocks a real submit outright, so the only way credentials leave
 * this page is the same-origin call below. With JavaScript broken, the form fails closed.
 */
import { useState, type FormEvent, type JSX, type ReactNode } from "react";
import { login } from "@/lib/account";
import type { AccountUser } from "@shared/protocol";

type Phase = "IDLE" | "SENDING" | "SIGNED_IN" | "REFUSED";

/**
 * Where an accepted account goes, and whether it needs to be told something first.
 *
 * `mustChangePassword` is set on an account whose first credential arrived out of band —
 * through an environment variable, which has been read by whoever configured the
 * deployment. Such an account may sign in and change its password and nothing else, so it
 * is sent to the account page rather than the administration surface, and told why.
 */
function destinationFor(user: AccountUser): { readonly path: string; readonly notice: string } {
  if (user.role === "ADMIN" && !user.mustChangePassword) {
    return { path: "/admin", notice: "" };
  }
  if (user.mustChangePassword) {
    return {
      path: "/account",
      notice: "a password change is required before this account may perform administrative actions",
    };
  }
  return { path: "/account", notice: "" };
}

/** A form row. The label column is fixed so the input cannot move when a message appears. */
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

export default function Login(): JSX.Element {
  const [email, setEmail] = useState<string>("");
  const [password, setPassword] = useState<string>("");
  const [phase, setPhase] = useState<Phase>("IDLE");
  const [reason, setReason] = useState<string>("");
  const [notice, setNotice] = useState<string>("");
  const [routingTo, setRoutingTo] = useState<string>("");

  const complete = email.trim().length > 0 && password.length > 0 && phase !== "SENDING";

  async function submit(event: FormEvent<HTMLFormElement>): Promise<void> {
    event.preventDefault();
    if (phase === "SENDING") return;

    setPhase("SENDING");
    setReason("");
    setNotice("");

    const result = await login(email.trim(), password);

    if (!result.ok) {
      // The server's own words, unedited and unattributed. Paraphrasing a refusal is how a
      // refusal becomes a mystery, and inventing a friendlier one is how it becomes wrong.
      setReason(result.reason);
      setPhase("REFUSED");
      return;
    }

    const target = destinationFor(result.value);
    // The password is cleared before navigating. Navigation is what should happen next,
    // but a page that leaves a credential in an input while it waits for an unload is a
    // page that leaves it there when the unload never comes.
    setPassword("");
    setRoutingTo(target.path);
    setPhase("SIGNED_IN");
    if (target.notice !== "") setNotice(target.notice);

    // A full page load rather than a client route: the session cookie is set by the
    // server's response, and reloading is what guarantees every page afterwards is served
    // with the new session rather than a cached render from before it existed.
    window.location.assign(target.path);
  }

  return (
    <div className="flex min-h-screen flex-col bg-void text-fg">
      <header className="flex h-[30px] shrink-0 items-center justify-between gap-4 border-b border-line bg-panel px-2 text-[10px] uppercase tracking-[0.18em]">
        <span className="flex items-center gap-3">
          <span className="text-fg">ZEUS // SIGN IN</span>
          <span className="text-dimmer">SESSION ISSUED SERVER-SIDE · NO TOKEN IN THIS BROWSER</span>
        </span>
        <span className="flex shrink-0 items-center gap-3">
          <a href="/signup" className="text-dim hover:text-fg">
            CREATE AN ACCOUNT
          </a>
          <a href="/privacy" className="text-dim hover:text-fg">
            PRIVACY
          </a>
          <a href="/" className="text-dim hover:text-fg">
            OPERATOR CONSOLE {"->"}
          </a>
        </span>
      </header>

      <main className="mx-auto flex w-full max-w-[880px] flex-1 flex-col px-4 py-6">
        <section className="flex flex-col gap-2 border-b border-line pb-4">
          <h1 className="text-[13px] uppercase tracking-[0.18em] text-fg">SIGN IN</h1>
          <p className="max-w-[70ch] text-[11px] leading-relaxed text-dim">
            One form for customers and administrators. The authority attached to an account is held on the server and
            read from it on every request; it is not sent to this page as something to be presented back, and nothing
            here selects it.
          </p>
          <p className="max-w-[70ch] text-[11px] leading-relaxed text-dimmer">
            A successful sign-in sets an HttpOnly, SameSite=Strict session cookie. This page cannot read it, an
            injected script cannot read it, and no part of the session is written to local storage or to a URL. Where
            you are sent next is decided from the role in the server&apos;s answer.
          </p>
        </section>

        <form onSubmit={(event) => void submit(event)} noValidate className="flex flex-col border-b border-line">
          <Row htmlFor="li-email" label="EMAIL" hint="the address the account was registered with">
            <input
              id="li-email"
              type="email"
              value={email}
              maxLength={254}
              autoComplete="off"
              spellCheck={false}
              onChange={(event) => setEmail(event.currentTarget.value)}
              className="w-full max-w-[420px] text-[11px]"
            />
          </Row>

          <Row htmlFor="li-password" label="PASSWORD" hint="at least 12 characters">
            <input
              id="li-password"
              type="password"
              value={password}
              maxLength={200}
              autoComplete="off"
              spellCheck={false}
              onChange={(event) => setPassword(event.currentTarget.value)}
              className="w-full max-w-[420px] text-[11px]"
            />
          </Row>

          <div className="flex items-center justify-between gap-4 py-4">
            <span className="text-[10px] uppercase tracking-[0.12em] text-dimmer">
              {phase === "SENDING" ? "TRANSMITTING" : "FAILED ATTEMPTS LOCK AN ACCOUNT FOR 15 MINUTES"}
            </span>
            <button
              type="submit"
              disabled={!complete}
              className="shrink-0 px-4 py-2 text-[10px] uppercase tracking-[0.18em]"
            >
              {phase === "SENDING" ? "[ SENDING ]" : "[ SIGN IN ]"}
            </button>
          </div>
        </form>

        <section className="flex flex-col gap-2 py-4" aria-live="polite">
          <span className="text-[10px] uppercase tracking-[0.18em] text-dimmer">OUTCOME</span>

          {phase === "IDLE" || phase === "SENDING" ? (
            <span className="text-[11px] text-dimmer">—</span>
          ) : phase === "SIGNED_IN" ? (
            <>
              <span className="text-[11px] uppercase tracking-[0.12em] text-clean">
                {`[+] ACCEPTED · SESSION ISSUED · ROUTING TO ${routingTo}`}
              </span>
              {/* Monochrome on purpose: this states a constraint, not a verdict. The three
                  state colours encode outcomes and refusal classes only, and spending one
                  here would dilute the one signal an operator scans for. */}
              {notice === "" ? null : (
                <span className="text-[11px] text-fg">{`[!] ${notice.toUpperCase()}`}</span>
              )}
              <p className="max-w-[70ch] text-[11px] leading-relaxed text-dimmer">
                If this page does not move on its own, the destination is shown above and can be opened directly.
              </p>
              <a href={routingTo} className="text-[11px] uppercase tracking-[0.12em] text-dim hover:text-fg">
                {`CONTINUE TO ${routingTo} {"->"}`}
              </a>
            </>
          ) : (
            <>
              <span className="text-[11px] uppercase tracking-[0.12em] text-flagged">{`[x] ${reason}`}</span>
              <p className="max-w-[70ch] text-[11px] leading-relaxed text-dimmer">
                The server answers identically for an unknown address and for a wrong password, on purpose, and spends
                the same hashing work on both so the reply time does not answer the question the message refuses to.
                Repeated failures lock the account briefly rather than permanently, since a permanent lock keyed on an
                address would be a denial of service against whoever owns it.
              </p>
            </>
          )}
        </section>
      </main>

      <footer className="flex shrink-0 flex-col gap-1 border-t border-line bg-panel px-3 py-2 text-[10px] leading-relaxed text-dimmer">
        <span>
          Session: one opaque random value in an HttpOnly, SameSite=Strict cookie. The server stores only a digest of
          it, so a copy of the session table grants no ability to present a session.
        </span>
        <span>
          Mutations additionally require a token the server derives from this session and returns to this page. It is
          held in memory only and written to no storage at all, and it changes when the session is re-issued — which is
          what a change in authority does.
        </span>
      </footer>
    </div>
  );
}
