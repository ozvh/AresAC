/**
 * Account page.
 *
 * WHAT THIS PAGE IS ALLOWED TO KNOW. It receives a description of the caller's own
 * account and nothing else. It cannot name a role and have it believed, it cannot ask for
 * another account's rows, and it cannot cancel a subscription that does not belong to the
 * session — because the server takes the owner from the session record, not from anything
 * this page sends. Every refusal below is the server's own sentence, rendered verbatim;
 * paraphrasing a refusal is how a refusal becomes a mystery.
 *
 * THE CANCELLATION ASYMMETRY IS THE POINT. Signing up requires three fields and three
 * consent decisions. Cancelling requires one button press: no confirmation dialog, no
 * reason field, no callback, no notice period, and no second step. The subscription runs
 * to the end of the period already paid for, so nothing is confiscated, and the button
 * that ends it is one click away from the page that shows it.
 *
 * NOTHING SUCKS THE USER INTO A SPINNER. While the account is loading, every readout
 * renders the fixed-width `—` placeholder, so the layout is already the final layout and
 * nothing moves when the values arrive.
 */
import { useCallback, useEffect, useState, type JSX, type ReactNode } from "react";
import { CONSENT_LABEL, PLAN_LABEL, type MeResponse } from "@shared/protocol";
import {
  UPLOAD_MAX_BYTES,
  UPLOAD_TYPES,
  cancelSubscription,
  changePassword,
  loadAccount,
  logout,
  setAutoRenew,
  uploadFile,
  type Outcome,
} from "@/lib/account";
import { pad } from "@/lib/format";

type Phase = "LOADING" | "READY" | "ANON";

/** Calendar day, fixed width. The account page compares dates, not instants. */
function day(ts: number): string {
  if (!Number.isFinite(ts) || ts <= 0) return "—";
  return new Date(ts).toISOString().slice(0, 10);
}

/** Byte size on a fixed grid, so a row cannot change width when a file changes. */
function size(bytes: number): string {
  if (!Number.isFinite(bytes) || bytes < 0) return "       —";
  if (bytes < 1_024) return `${pad(bytes, 5)} B  `;
  if (bytes < 1_048_576) return `${(bytes / 1_024).toFixed(1).padStart(6)} KiB`;
  return `${(bytes / 1_048_576).toFixed(1).padStart(6)} MiB`;
}

/** Minor units to a fixed-width amount. Zero is stated as zero, not left blank. */
function money(cents: number): string {
  if (!Number.isFinite(cents)) return "—";
  if (cents === 0) return "no charge";
  return `${(cents / 100).toFixed(2).padStart(8)}`;
}

const UPLOAD_CEILING = Math.floor(UPLOAD_MAX_BYTES / 1024);

/** A bordered section with the standard header bar. */
function Panel({
  title,
  meta,
  children,
}: {
  title: string;
  meta: string;
  children: ReactNode;
}): JSX.Element {
  return (
    <section className="flex flex-col border-b border-line bg-panel">
      <header className="flex h-[22px] shrink-0 items-center justify-between border-b border-line px-2 text-[10px] uppercase tracking-[0.18em]">
        <span className="text-fg">{title}</span>
        <span className="text-dimmer">{meta}</span>
      </header>
      <div className="flex flex-col gap-3 p-3">{children}</div>
    </section>
  );
}

/** One label/value readout. The label column is fixed so values never shift. */
function Field({ label, value, tone = "text-fg" }: { label: string; value: string; tone?: string }): JSX.Element {
  return (
    <div className="grid grid-cols-[190px_minmax(0,1fr)] gap-x-4">
      <span className="text-[10px] uppercase tracking-[0.12em] text-dimmer">{label}</span>
      <span className={`num break-all text-[11px] ${tone}`}>{value}</span>
    </div>
  );
}

export default function Account(): JSX.Element {
  const [phase, setPhase] = useState<Phase>("LOADING");
  const [account, setAccount] = useState<MeResponse | null>(null);
  const [refusal, setRefusal] = useState<string>("");
  const [notice, setNotice] = useState<string>("");
  const [busy, setBusy] = useState<string | null>(null);

  const [current, setCurrent] = useState<string>("");
  const [next, setNext] = useState<string>("");
  const [confirm, setConfirm] = useState<string>("");

  const reload = useCallback(async (): Promise<void> => {
    const result = await loadAccount();
    if (!result.ok) {
      // A session that has ended is not an error to shout about; it is a state to render.
      setAccount(null);
      setPhase("ANON");
      return;
    }
    setAccount(result.value);
    setPhase("READY");
  }, []);

  useEffect(() => {
    void reload();
  }, [reload]);

  /**
   * Run one server call and report its answer.
   *
   * Nothing is optimistically rendered: the success text appears only after the arbiter's
   * own reply, and a failure shows the server's exact sentence with `[x]`.
   */
  async function run<T>(label: string, action: () => Promise<Outcome<T>>, success: string): Promise<boolean> {
    if (busy !== null) return false;
    setBusy(label);
    setRefusal("");
    setNotice("");
    const result = await action();
    if (result.ok) {
      setNotice(success);
      await reload();
    } else {
      setRefusal(result.reason);
    }
    setBusy(null);
    return result.ok;
  }

  const subscription = account === null ? null : account.subscription;
  const user = account === null ? null : account.user;

  /* ---------------- signed out ---------------- */

  if (phase === "ANON") {
    return (
      <div className="flex min-h-screen flex-col bg-void text-fg">
        <header className="flex h-[30px] shrink-0 items-center justify-between gap-4 border-b border-line bg-panel px-2 text-[10px] uppercase tracking-[0.18em]">
          <span className="flex items-center gap-3">
            <span className="text-fg">ZEUS // ACCOUNT</span>
            <span className="text-flagged">NO SESSION</span>
          </span>
          <a href="/" className="text-dim hover:text-fg">
            OPERATOR CONSOLE {"->"}
          </a>
        </header>
        <main className="mx-auto flex w-full max-w-[880px] flex-1 flex-col gap-4 px-4 py-6">
          <section className="flex flex-col gap-3 border border-line bg-panel p-4">
            <h1 className="text-[13px] uppercase tracking-[0.18em] text-fg">NOT SIGNED IN</h1>
            <p className="max-w-[70ch] text-[11px] leading-relaxed text-dim">
              This page describes one account and needs a live session to do it. A session is a record held
              server-side and carried in a cookie the page itself cannot read, so nothing here can be recovered or
              reconstructed without one.
            </p>
            <p className="max-w-[70ch] text-[11px] leading-relaxed text-dimmer">
              {refusal === "" ? "The session is absent or has expired." : `[x] ${refusal}`}
            </p>
            <div className="flex items-center gap-3 pt-1">
              <a
                href="/login"
                className="border border-line px-4 py-2 text-[10px] uppercase tracking-[0.18em] text-fg"
              >
                [ SIGN IN ]
              </a>
              <a
                href="/signup"
                className="border border-line px-4 py-2 text-[10px] uppercase tracking-[0.18em] text-dim"
              >
                [ CREATE ACCOUNT ]
              </a>
            </div>
          </section>
        </main>
      </div>
    );
  }

  return (
    <div className="flex min-h-screen flex-col bg-void text-fg">
      <header className="flex h-[30px] shrink-0 items-center justify-between gap-4 border-b border-line bg-panel px-2 text-[10px] uppercase tracking-[0.18em]">
        <span className="flex items-center gap-3">
          <span className="text-fg">ZEUS // ACCOUNT</span>
          <span className={phase === "READY" ? "text-fg" : "text-dimmer"}>
            {phase === "READY" && user !== null ? user.email : "LOADING"}
          </span>
          {user !== null && user.role === "ADMIN" ? <span className="text-dim">ROLE ADMIN</span> : null}
        </span>
        <span className="flex shrink-0 items-center gap-4">
          {user !== null && user.role === "ADMIN" ? (
            <a href="/admin" className="text-dim hover:text-fg">
              ADMINISTRATION {"->"}
            </a>
          ) : null}
          <a href="/request" className="text-dim hover:text-fg">
            BUILD REQUEST {"->"}
          </a>
          <a href="/" className="text-dim hover:text-fg">
            OPERATOR CONSOLE {"->"}
          </a>
        </span>
      </header>

      <main className="mx-auto flex w-full max-w-[880px] flex-1 flex-col px-4 py-6">
        {/* The one place a refusal or a confirmation is reported. Nothing else on this
            page reports the outcome of an action, so a refusal cannot be mistaken for
            a success. */}
        <div aria-live="polite" className="flex flex-col gap-1 border-b border-line pb-3">
          <span className="text-[10px] uppercase tracking-[0.18em] text-dimmer">LAST ANSWER</span>
          {refusal !== "" ? (
            <span className="text-[11px] text-flagged">{`[x] ${refusal}`}</span>
          ) : notice !== "" ? (
            <span className="text-[11px] text-clean">{`[+] ${notice}`}</span>
          ) : busy !== null ? (
            <span className="text-[11px] text-dim">{`[~] ${busy} IN FLIGHT`}</span>
          ) : (
            <span className="text-[11px] text-dimmer">—</span>
          )}
        </div>

        {user !== null && user.mustChangePassword ? (
          <section className="flex flex-col gap-2 border-b border-line bg-panel px-3 py-3">
            <span className="text-[11px] uppercase tracking-[0.12em] text-pending">
              [!] THIS PASSWORD MUST BE CHANGED
            </span>
            <p className="max-w-[70ch] text-[11px] leading-relaxed text-dim">
              This account was created with a credential that was set outside the interface, so it has been seen by
              whoever configured the deployment. Every administrative action is refused until it is replaced. Use the
              PASSWORD section below.
            </p>
          </section>
        ) : null}

        {/* ---------- 1. identity ---------- */}
        <Panel title="IDENTITY" meta={phase === "READY" ? "READ FROM THE SESSION RECORD" : "LOADING"}>
          <Field label="DISPLAY NAME" value={user === null ? "—" : user.displayName} />
          <Field label="ADDRESS" value={user === null ? "—" : user.email} />
          <Field label="ROLE" value={user === null ? "—" : user.role} />
          <Field
            label="SESSION EXPIRES"
            value="managed server-side; the browser holds an opaque identifier only"
            tone="text-dimmer"
          />
          <div className="flex flex-col gap-1 border-t border-line pt-2">
            <span className="text-[10px] uppercase tracking-[0.12em] text-dimmer">CONSENT ON RECORD</span>
            {account === null || account.consents.length === 0 ? (
              <span className="num text-[11px] text-dimmer">—</span>
            ) : (
              account.consents.map((consent) => (
                <span key={`${consent.kind}-${consent.version}`} className="flex items-baseline gap-3 text-[11px]">
                  <span className="num w-[52px] shrink-0 text-dimmer">{consent.kind}</span>
                  <span className="w-[248px] shrink-0 text-dim">{CONSENT_LABEL[consent.kind]}</span>
                  <span className="num w-[68px] shrink-0 text-dimmer">v{consent.version}</span>
                  <span className="num w-[86px] shrink-0 text-dim">{day(consent.grantedAt)}</span>
                  <span className={consent.withdrawn ? "text-flagged" : "text-dimmer"}>
                    {consent.withdrawn ? "[x] WITHDRAWN" : "HELD"}
                  </span>
                </span>
              ))
            )}
          </div>
        </Panel>

        {/* ---------- 2. subscription ---------- */}
        <Panel
          title="SUBSCRIPTION"
          meta={subscription === null ? (phase === "READY" ? "NONE RECORDED" : "LOADING") : subscription.status}
        >
          {subscription === null ? (
            <>
              <Field label="PLAN" value="—" />
              <p className="max-w-[70ch] text-[11px] leading-relaxed text-dim">
                This account has no subscription. Builds are issued by request rather than sold from this page, so a
                request starts the process and the maintainer sets the term when the build is prepared.
              </p>
              <a href="/request" className="w-fit border border-line px-4 py-2 text-[10px] uppercase tracking-[0.18em] text-dim">
                [ REQUEST A BUILD ]
              </a>
            </>
          ) : (
            <>
              <Field label="PLAN" value={PLAN_LABEL[subscription.plan]} />
              <Field label="STATUS" value={subscription.status} />
              <Field label="AMOUNT PER PERIOD" value={money(subscription.amountCents)} />
              <Field label="CURRENT PERIOD ENDS" value={day(subscription.currentPeriodEnd)} />
              <Field
                label="AUTO-RENEW"
                value={subscription.autoRenew ? "ON" : "OFF"}
                tone={subscription.autoRenew ? "text-fg" : "text-dimmer"}
              />
              <Field
                label="RENEWAL NOTICE"
                value={`emailed ${subscription.noticeDays} days before the period end, once per period`}
              />
              {subscription.cancelEffectiveAt === null ? null : (
                <Field label="SERVICE ENDS" value={day(subscription.cancelEffectiveAt)} />
              )}

              <div className="flex flex-col gap-2 border-t border-line pt-2">
                <div className="flex flex-wrap items-center gap-3">
                  <button
                    type="button"
                    className="text-[10px] uppercase"
                    disabled={busy !== null || !subscription.autoRenew}
                    onClick={() =>
                      void run(
                        "CANCEL AUTO-RENEW",
                        () => cancelSubscription(subscription.id),
                        "auto-renew is off; your term runs to its end",
                      )
                    }
                  >
                    [ CANCEL AUTO-RENEW ]
                  </button>
                  <button
                    type="button"
                    className="text-[10px] uppercase"
                    disabled={busy !== null}
                    onClick={() =>
                      void run(
                        subscription.autoRenew ? "AUTO-RENEW OFF" : "AUTO-RENEW ON",
                        () => setAutoRenew(subscription.id, !subscription.autoRenew),
                        subscription.autoRenew ? "auto-renew disabled" : "auto-renew enabled",
                      )
                    }
                  >
                    {subscription.autoRenew ? "[ SWITCH AUTO-RENEW OFF ]" : "[ SWITCH AUTO-RENEW ON ]"}
                  </button>
                </div>
                <p className="max-w-[70ch] text-[11px] leading-relaxed text-dim">
                  Cancelling is this one action. There is no confirmation step, no reason to give, no call to book and
                  no notice period — deliberately fewer steps than creating the account took. The period you have
                  already paid for runs to {day(subscription.currentPeriodEnd)}; nothing else is taken.
                </p>
                <p className="max-w-[70ch] text-[11px] leading-relaxed text-dimmer">
                  A notice goes to {user === null ? "your address" : user.email} {subscription.noticeDays} days before
                  every renewal, once per period, stating the date and the amount and how to stop it.
                </p>
              </div>
            </>
          )}
        </Panel>

        {/* ---------- 3. uploads ---------- */}
        <Panel
          title="UPLOADED ARTEFACTS"
          meta={
            account === null
              ? "LOADING"
              : `${account.uploads.length} RETAINED · DELETED AFTER ${account.retentionDays} DAYS`
          }
        >
          <div className="flex flex-wrap items-center gap-3">
            <input
              type="file"
              aria-label="attach an artefact"
              accept={UPLOAD_TYPES.join(",")}
              disabled={busy !== null}
              className="text-[11px]"
              onChange={(event) => {
                const file = event.currentTarget.files?.[0];
                if (file === undefined) return;
                // Reset the control so selecting the same file twice still fires.
                event.currentTarget.value = "";
                void run("UPLOAD", () => uploadFile(file, null), "artefact accepted and stored");
              }}
            />
            <span className="num text-[10px] text-dimmer">
              {`CEILING ${pad(UPLOAD_CEILING, 3)} KiB · TYPES ${UPLOAD_TYPES.length}`}
            </span>
          </div>
          <p className="max-w-[70ch] text-[11px] leading-relaxed text-dim">
            Content is identified from its bytes, not its name: a container or an executable is refused even when it
            arrives named as an image, and a declared type that disagrees with the content is refused. Stored files
            are renamed, written outside every served directory, and never served back.
          </p>
          <p className="max-w-[70ch] text-[11px] leading-relaxed text-dimmer">
            {account === null
              ? "—"
              : `Files are deleted automatically ${account.retentionDays} days after upload, and the deletion is recorded. The window is the same number stated in the privacy policy.`}
          </p>

          <div className="flex flex-col border-t border-line pt-2">
            <span className="flex items-baseline gap-3 text-[10px] uppercase tracking-[0.12em] text-dimmer">
              <span className="w-[240px] shrink-0">ORIGINAL NAME</span>
              <span className="w-[86px] shrink-0 text-right">BYTES</span>
              <span className="w-[86px] shrink-0">VERDICT</span>
              <span className="w-[86px] shrink-0">CREATED</span>
              <span className="w-[86px] shrink-0">EXPIRES</span>
            </span>
            {account === null || account.uploads.length === 0 ? (
              <span className="num py-1 text-[11px] text-dimmer">—</span>
            ) : (
              account.uploads.map((upload) => (
                <span key={upload.id} className="flex items-baseline gap-3 border-b border-line py-1 text-[11px]">
                  <span className="w-[240px] shrink-0 truncate text-fg" title={upload.originalName}>
                    {upload.originalName}
                  </span>
                  <span className="num w-[86px] shrink-0 text-right text-dim">{size(upload.bytes)}</span>
                  <span
                    className={`w-[86px] shrink-0 ${
                      upload.verdict === "ACCEPTED"
                        ? "text-clean"
                        : upload.verdict === "REJECTED"
                          ? "text-flagged"
                          : "text-pending"
                    }`}
                  >
                    {upload.verdict}
                  </span>
                  <span className="num w-[86px] shrink-0 text-dim">{day(upload.createdAt)}</span>
                  <span className={`num w-[86px] shrink-0 ${upload.deleted ? "text-flagged" : "text-dimmer"}`}>
                    {upload.deleted ? "DELETED" : day(upload.expiresAt)}
                  </span>
                </span>
              ))
            )}
          </div>
        </Panel>

        {/* ---------- 4. password ---------- */}
        <Panel title="PASSWORD" meta={user !== null && user.mustChangePassword ? "CHANGE REQUIRED" : "OPTIONAL"}>
          <div className="grid grid-cols-[190px_minmax(0,1fr)] items-center gap-x-4 gap-y-2">
            <label htmlFor="ac-current" className="text-[10px] uppercase tracking-[0.12em] text-dimmer">
              CURRENT
            </label>
            <input
              id="ac-current"
              type="password"
              value={current}
              autoComplete="current-password"
              spellCheck={false}
              onChange={(event) => setCurrent(event.currentTarget.value)}
              className="w-full max-w-[420px] text-[11px]"
            />
            <label htmlFor="ac-next" className="text-[10px] uppercase tracking-[0.12em] text-dimmer">
              NEW
            </label>
            <input
              id="ac-next"
              type="password"
              value={next}
              autoComplete="new-password"
              spellCheck={false}
              onChange={(event) => setNext(event.currentTarget.value)}
              className="w-full max-w-[420px] text-[11px]"
            />
            <label htmlFor="ac-confirm" className="text-[10px] uppercase tracking-[0.12em] text-dimmer">
              REPEAT NEW
            </label>
            <input
              id="ac-confirm"
              type="password"
              value={confirm}
              autoComplete="new-password"
              spellCheck={false}
              onChange={(event) => setConfirm(event.currentTarget.value)}
              className="w-full max-w-[420px] text-[11px]"
            />
          </div>
          <div className="flex flex-wrap items-center gap-3">
            <button
              type="button"
              className="text-[10px] uppercase"
              disabled={busy !== null || current === "" || next === "" || next !== confirm}
              onClick={() => {
                // The button is disabled while the two new passwords differ, so this only
                // ever runs with a matching pair; the server re-checks the policy itself.
                void run(
                  "CHANGE PASSWORD",
                  () => changePassword(current, next),
                  "password changed; all other sessions were signed out",
                ).then((applied) => {
                  // Cleared only when the server accepted it. Emptying the fields after a
                  // refusal would make the user retype a password the server never saw.
                  if (!applied) return;
                  setCurrent("");
                  setNext("");
                  setConfirm("");
                });
              }}
            >
              [ CHANGE PASSWORD ]
            </button>
            <span className="text-[10px] text-dimmer">
              {next !== "" && next !== confirm ? "[!] THE TWO NEW PASSWORDS DIFFER" : "12 CHARACTERS MINIMUM"}
            </span>
          </div>
          <p className="max-w-[70ch] text-[11px] leading-relaxed text-dim">
            Changing the password ends every other session on this account immediately, and this device is given a
            fresh one. A password change that left an existing session alive would not have changed anything that
            matters.
          </p>
          <p className="max-w-[70ch] text-[11px] leading-relaxed text-dimmer">
            Stored as a salted, memory-hard digest. The password itself is never written to a record, never logged,
            and cannot be read back from the database.
          </p>
        </Panel>

        {/* ---------- 5. session ---------- */}
        <Panel title="SESSION" meta={phase === "READY" ? "ACTIVE" : "LOADING"}>
          <Field label="HELD AS" value="an opaque server-side record; the cookie is unreadable by script" tone="text-dim" />
          <Field
            label="WRITE TOKEN"
            value="derived by the server from this session and read back on load; held in memory, stable for the session"
            tone="text-dim"
          />
          <div className="flex flex-wrap items-center gap-3 border-t border-line pt-2">
            <button
              type="button"
              className="text-[10px] uppercase"
              disabled={busy !== null}
              onClick={() => {
                void logout().then(() => window.location.assign("/"));
              }}
            >
              [ SIGN OUT ]
            </button>
            <span className="text-[10px] text-dimmer">REVOKES THIS SESSION RECORD AND CLEARS THE COOKIE</span>
          </div>
        </Panel>
      </main>

      <footer className="flex shrink-0 flex-col gap-1 border-t border-line bg-panel px-3 py-2 text-[10px] leading-relaxed text-dimmer">
        <span>
          This page reads one account. It cannot ask for another: the owner of every row is taken from the session
          record on the server, so no field here could redirect a request at somebody else&apos;s data.
        </span>
        <span>
          Nothing on this page is stored in the browser. The session is a server-side record behind an HttpOnly
          cookie, and the synchroniser token the buttons send lives in memory for this session and is written to no
          storage.
        </span>
      </footer>
    </div>
  );
}
