/**
 * Administration.
 *
 * WHAT THIS PAGE IS AND IS NOT.
 *
 * It is a view onto server state that the server decided this account may see. It is not
 * a place where authority is granted. Every read below is refused by the server when the
 * caller is not an administrator, and every mutation is refused as well — with the
 * caller's own role re-derived from the session record on each request. Nothing rendered
 * here is a permission; the buttons are hidden or disabled to avoid offering an action
 * that would fail, and the failure would happen anyway if they were not.
 *
 * A refusal and an empty result are rendered differently on purpose. If `loadAdminSummary`
 * fails, this page shows a DENIED state carrying the server's own wording. It does not
 * render empty tables, because a table with no rows reads as "there is nothing here",
 * which is the opposite of "you were not allowed to look" — and a console that conflates
 * the two teaches its operator to misread both.
 *
 * The audit section is the reason this page exists at all. It shows what the server
 * recorded: who acted, on what, and whether it was allowed. The records are append-only
 * in the engine, not in this file, so an attempt to rewrite history fails in the database
 * rather than in application code.
 */
import { useCallback, useEffect, useState, type JSX } from "react";
import type {
  AccountRole,
  AccountStatus,
  AccountUser,
  AdminAuditView,
  AdminUserView,
} from "@shared/protocol";
import { PLAN_LABEL } from "@shared/protocol";
import {
  currentSession,
  loadAdminAudit,
  loadAdminUsers,
  loadAdminSummary,
  logout,
  refreshSession,
  updateAdminUser,
  type AdminSummary,
} from "@/lib/account";
import { clock, compact, padZero } from "@/lib/format";

type Phase = "LOADING" | "READY" | "DENIED";

/** Fixed-width calendar day. `clock` is a wall clock; a record needs a date. */
function day(ts: number | null): string {
  if (ts === null || !Number.isFinite(ts) || ts <= 0) return "—";
  const d = new Date(ts);
  return `${d.getFullYear()}-${padZero(d.getMonth() + 1, 2)}-${padZero(d.getDate(), 2)}`;
}

const ROLE_TEXT: Readonly<Record<AccountRole, string>> = { CUSTOMER: "CUSTOMER", ADMIN: "ADMIN" };

function Section({ title, meta, children }: { title: string; meta: string; children: JSX.Element }): JSX.Element {
  return (
    <section className="flex flex-col border-b border-line bg-panel">
      <header className="flex h-[22px] shrink-0 items-center justify-between gap-4 border-b border-line px-2 text-[10px] uppercase tracking-[0.18em]">
        <span className="text-fg">{title}</span>
        <span className="num shrink-0 text-dimmer">{meta}</span>
      </header>
      <div className="p-2">{children}</div>
    </section>
  );
}

function Cell({ label, value, tone = "text-fg" }: { label: string; value: string; tone?: string }): JSX.Element {
  return (
    <div className="flex items-baseline gap-2">
      <dt className="w-[196px] shrink-0 text-[10px] uppercase tracking-[0.12em] text-dimmer">{label}</dt>
      <dd className={`num text-[11px] ${tone}`}>{value}</dd>
    </div>
  );
}

export default function Admin(): JSX.Element {
  const [phase, setPhase] = useState<Phase>("LOADING");
  const [denial, setDenial] = useState<string>("");
  const [summary, setSummary] = useState<AdminSummary | null>(null);
  const [users, setUsers] = useState<readonly AdminUserView[]>([]);
  const [audit, setAudit] = useState<readonly AdminAuditView[]>([]);
  const [identity, setIdentity] = useState<AccountUser | null>(null);
  const [notice, setNotice] = useState<string>("");
  const [refused, setRefused] = useState<boolean>(false);
  const [busy, setBusy] = useState<string>("");

  const load = useCallback(async (): Promise<void> => {
    setNotice("");
    setRefused(false);
    await refreshSession();
    const session = currentSession();
    setIdentity(session.status === "AUTHED" ? session.user : null);

    const head = await loadAdminSummary();
    if (!head.ok) {
      // The server's own words. Paraphrasing a refusal is how a refusal becomes a mystery.
      setDenial(head.reason);
      setPhase("DENIED");
      return;
    }
    setSummary(head.value);

    const list = await loadAdminUsers();
    if (list.ok) setUsers(list.value);
    const log = await loadAdminAudit();
    if (log.ok) setAudit(log.value);
    setPhase("READY");
  }, []);

  useEffect(() => {
    void load();
  }, [load]);

  async function mutate(
    label: string,
    userId: string,
    patch: { readonly role: AccountRole | null; readonly status: AccountStatus | null },
  ): Promise<void> {
    if (busy !== "") return;
    setBusy(`${label}:${userId}`);
    setNotice("");
    setRefused(false);

    const result = await updateAdminUser({ userId, role: patch.role, status: patch.status });
    if (!result.ok) {
      setRefused(true);
      setNotice(`[x] ${label} REFUSED · ${result.reason}`);
      setBusy("");
      return;
    }

    // Reload rather than patching the row locally: the server is the authority on what the
    // account is now, and a locally patched row would show a change the server refused.
    const list = await loadAdminUsers();
    if (list.ok) setUsers(list.value);
    const log = await loadAdminAudit();
    if (log.ok) setAudit(log.value);
    const head = await loadAdminSummary();
    if (head.ok) setSummary(head.value);
    setNotice(`[+] ${label} ACCEPTED · recorded in the audit log`);
    setBusy("");
  }

  const selfId = identity === null ? "" : identity.email;
  const newestFirst = [...audit].sort((a, b) => b.seq - a.seq);

  return (
    <div className="flex min-h-screen flex-col bg-void text-fg">
      <header className="flex h-[30px] shrink-0 items-center justify-between gap-4 border-b border-line bg-panel px-2 text-[10px] uppercase tracking-[0.18em]">
        <span className="flex items-center gap-3">
          <span className="text-fg">ZEUS // ADMINISTRATION</span>
          <span className="text-dimmer">SERVER-AUTHORISED · EVERY ACTION AUDITED</span>
        </span>
        <span className="flex items-center gap-3">
          <a href="/account" className="text-dim hover:text-fg">
            ACCOUNT {"->"}
          </a>
          <a href="/" className="text-dim hover:text-fg">
            CONSOLE {"->"}
          </a>
        </span>
      </header>

      <main className="mx-auto flex w-full max-w-[1180px] flex-1 flex-col gap-3 px-3 py-4">
        {/* ---------- audit of the operator's own actions ---------- */}
        <div aria-live="polite" className="flex min-h-[20px] items-baseline gap-2 text-[11px]">
          {notice === "" ? (
            <span className="text-[10px] uppercase tracking-[0.12em] text-dimmer">
              NO ADMINISTRATIVE ACTION ISSUED THIS SESSION
            </span>
          ) : (
            <span className={`num break-all ${refused ? "text-flagged" : "text-fg"}`}>{notice}</span>
          )}
        </div>

        {phase === "LOADING" ? (
          <p className="text-[11px] text-dimmer">requesting state from the server…</p>
        ) : phase === "DENIED" ? (
          <section className="flex flex-col gap-2 border border-line bg-panel p-4">
            <span className="text-[11px] uppercase tracking-[0.12em] text-flagged">[x] DENIED</span>
            <span className="num break-all text-[11px] text-flagged">{denial}</span>
            <p className="max-w-[78ch] text-[11px] leading-relaxed text-dim">
              Administrative routes are refused by the server, not by this page. The server re-derives the caller&apos;s
              role from the session record on every request, so a page cannot grant what the account does not hold. Two
              conditions produce exactly this refusal: the account is not an administrator, or the account is a
              bootstrap administrator whose password has not yet been changed — a credential that arrived through the
              environment buys a password change and nothing else.
            </p>
            <p className="max-w-[78ch] text-[11px] leading-relaxed text-dimmer">
              No account data was read before the refusal. The check runs ahead of every query, so a refused request
              does not leave the server having looked at rows on behalf of a caller who was not allowed to see them.
            </p>
            <span className="flex items-center gap-3 pt-1">
              <a href="/account" className="text-[10px] uppercase tracking-[0.12em] text-dim hover:text-fg">
                [ GO TO ACCOUNT ]
              </a>
              <a href="/login" className="text-[10px] uppercase tracking-[0.12em] text-dim hover:text-fg">
                [ SIGN IN AS ANOTHER ACCOUNT ]
              </a>
            </span>
          </section>
        ) : (
          <>
            {/* ---------- 1. state ---------- */}
            <Section
              title="STATE"
              meta={summary === null ? "—" : `${compact(summary.auditRecords)} AUDIT RECORDS`}
            >
              <div className="flex flex-col gap-4">
                <dl className="grid grid-cols-[minmax(0,1fr)_minmax(0,1fr)] gap-x-8 gap-y-1">
                  <Cell label="CUSTOMER ACCOUNTS" value={summary === null ? "—" : String(summary.customers)} />
                  <Cell label="ADMINISTRATOR ACCOUNTS" value={summary === null ? "—" : String(summary.admins)} />
                  <Cell label="AUDIT RECORDS RETAINED" value={summary === null ? "—" : compact(summary.auditRecords)} />
                  <Cell
                    label="UPLOAD RETENTION"
                    value={summary === null ? "—" : `${String(summary.retentionDays).padStart(3, " ")} DAYS`}
                  />
                  <Cell
                    label="RENEWAL NOTICE LEAD"
                    value={summary === null ? "—" : `${String(summary.noticeDays).padStart(3, " ")} DAYS`}
                  />
                  <Cell
                    label="BUILD REQUESTS ACCEPTED"
                    value={summary === null ? "—" : compact(summary.buildRequests)}
                  />
                </dl>
                <div className="flex flex-col gap-1 border-t border-line pt-2">
                  <span className="text-[10px] uppercase tracking-[0.12em] text-dimmer">PLANS OFFERED</span>
                  {summary === null || summary.plans.length === 0 ? (
                    <span className="text-[11px] text-dimmer">—</span>
                  ) : (
                    summary.plans.map((plan) => {
                      const label = plan === "EVALUATION" || plan === "RETAIL" || plan === "SOURCE" ? PLAN_LABEL[plan] : plan;
                      return (
                        <span key={plan} className="text-[11px] text-dim">
                          {plan} · {label}
                        </span>
                      );
                    })
                  )}
                </div>
                <p className="max-w-[96ch] text-[10px] leading-relaxed text-dimmer">
                  Retention and notice figures are read from the server&apos;s live configuration, so the number stated
                  here is the number the sweeper acts on. The privacy policy states the same retention window; if one
                  changes, the other has to change with it.
                </p>
                <button type="button" className="self-start text-[10px] uppercase" onClick={() => void load()}>
                  [ RELOAD STATE ]
                </button>
              </div>
            </Section>

            {/* ---------- 2. accounts ---------- */}
            <Section
              title="ACCOUNTS"
              meta={`${users.length} RETURNED · ${users.filter((row) => row.role === "ADMIN").length} ADMIN`}
            >
              <div className="flex flex-col">
                <div className="grid grid-cols-[68px_minmax(0,1fr)_140px_76px_80px_92px_92px_230px] items-baseline gap-2 border-b border-line pb-1 text-[10px] uppercase tracking-[0.12em] text-dimmer">
                  <span>ID</span>
                  <span>ADDRESS</span>
                  <span>NAME</span>
                  <span>ROLE</span>
                  <span>STATUS</span>
                  <span>CREATED</span>
                  <span>LAST SIGN-IN</span>
                  <span>AUTHORITY</span>
                </div>

                {users.length === 0 ? (
                  <p className="py-3 text-[11px] text-dimmer">
                    the server returned no accounts · this is an empty result, not a refusal
                  </p>
                ) : (
                  users.map((user) => {
                    const own = user.email === selfId;
                    const working = busy.endsWith(`:${user.id}`);
                    const promote = user.role === "CUSTOMER";
                    const suspend = user.status === "ACTIVE";
                    return (
                      <div
                        key={user.id}
                        className="grid grid-cols-[68px_minmax(0,1fr)_140px_76px_80px_92px_92px_230px] items-baseline gap-2 border-b border-line py-1 text-[11px]"
                      >
                        <span className="num truncate text-dim" title={user.id}>
                          {user.id.slice(0, 8)}
                        </span>
                        <span className="truncate text-fg" title={user.email}>
                          {user.email}
                        </span>
                        <span className="truncate text-dim" title={user.displayName}>
                          {user.displayName}
                        </span>
                        <span className={user.role === "ADMIN" ? "text-fg" : "text-dim"}>{ROLE_TEXT[user.role]}</span>
                        <span className={user.status === "ACTIVE" ? "text-dim" : "text-pending"}>{user.status}</span>
                        <span className="num text-dim">{day(user.createdAt)}</span>
                        <span className="num text-dim">{day(user.lastLoginAt)}</span>
                        <span className="flex items-baseline gap-1">
                          {own ? (
                            <span className="text-[10px] uppercase tracking-[0.12em] text-dimmer">
                              OWN ACCOUNT · NOT CHANGEABLE
                            </span>
                          ) : (
                            <>
                              <button
                                type="button"
                                className="text-[10px] uppercase"
                                disabled={working}
                                onClick={() =>
                                  void mutate(promote ? "PROMOTE" : "DEMOTE", user.id, {
                                    role: promote ? "ADMIN" : "CUSTOMER",
                                    status: null,
                                  })
                                }
                              >
                                {promote ? "[ PROMOTE ]" : "[ DEMOTE ]"}
                              </button>
                              <button
                                type="button"
                                className="text-[10px] uppercase"
                                disabled={working}
                                onClick={() =>
                                  void mutate(suspend ? "SUSPEND" : "RESTORE", user.id, {
                                    role: null,
                                    status: suspend ? "SUSPENDED" : "ACTIVE",
                                  })
                                }
                              >
                                {suspend ? "[ SUSPEND ]" : "[ RESTORE ]"}
                              </button>
                            </>
                          )}
                        </span>
                      </div>
                    );
                  })
                )}

                <p className="max-w-[96ch] pt-2 text-[10px] leading-relaxed text-dimmer">
                  An administrator cannot change their own authority and the server refuses it independently of this
                  page, because an administrator who can demote themselves can remove the last account capable of
                  administering the system. The last remaining administrator cannot be demoted or suspended either.
                  Suspending an account ends its sessions in the same transaction, so a suspended session does not
                  survive until its stated expiry.
                </p>
              </div>
            </Section>

            {/* ---------- 3. audit ---------- */}
            <Section title="AUDIT LOG" meta={`${newestFirst.length} MOST RECENT · NEWEST FIRST`}>
              <div className="flex flex-col">
                <div className="grid grid-cols-[58px_92px_72px_190px_72px_minmax(0,1fr)] items-baseline gap-2 border-b border-line pb-1 text-[10px] uppercase tracking-[0.12em] text-dimmer">
                  <span>SEQ</span>
                  <span>TIME</span>
                  <span>ACTOR</span>
                  <span>ACTION</span>
                  <span>OUTCOME</span>
                  <span>DETAIL</span>
                </div>

                {newestFirst.length === 0 ? (
                  <p className="py-3 text-[11px] text-dimmer">
                    the server returned no audit records · this is an empty result, not a refusal
                  </p>
                ) : (
                  newestFirst.map((record) => (
                    <div
                      key={record.seq}
                      className="grid grid-cols-[58px_92px_72px_190px_72px_minmax(0,1fr)] items-baseline gap-2 border-b border-line py-1 text-[11px]"
                    >
                      <span className="num text-dimmer">{`#${String(record.seq).padStart(5, "0")}`}</span>
                      <span className="num text-dim">{clock(record.ts)}</span>
                      <span className={record.actorRole === "ADMIN" ? "text-fg" : "text-dim"}>{record.actorRole}</span>
                      <span className="truncate text-fg" title={record.action}>
                        {record.action}
                      </span>
                      {/* The only coloured cell in this page: a refusal is a refusal class. */}
                      <span className={record.outcome === "REFUSED" ? "text-flagged" : "text-dim"}>
                        {record.outcome}
                      </span>
                      <span className="truncate text-dim" title={record.detail}>
                        {record.detail}
                      </span>
                    </div>
                  ))
                )}

                <p className="max-w-[96ch] pt-2 text-[10px] leading-relaxed text-dimmer">
                  The log is append-only and the rule is enforced by database triggers, not by application code:
                  <span className="text-dim"> UPDATE </span> and <span className="text-dim"> DELETE </span> against a
                  stored record raise an error inside the engine, so an edit to a historical row is refused even by a
                  process that has full write access to the database file. Every authentication, authorisation refusal,
                  account change, subscription transition, upload verdict and retention deletion writes here, and there
                  is no code path that removes a record.
                </p>
              </div>
            </Section>

            {/* ---------- 4. session ---------- */}
            <Section title="SESSION" meta={identity === null ? "UNKNOWN" : identity.role}>
              <div className="flex flex-col gap-3">
                <dl className="flex flex-col gap-1">
                  <Cell label="SIGNED IN AS" value={identity === null ? "—" : identity.email} />
                  <Cell label="DISPLAY NAME" value={identity === null ? "—" : identity.displayName} />
                  <Cell label="ROLE" value={identity === null ? "—" : identity.role} />
                  <Cell
                    label="PASSWORD CHANGE REQUIRED"
                    value={identity === null ? "—" : identity.mustChangePassword ? "TRUE" : "FALSE"}
                    tone={identity !== null && identity.mustChangePassword ? "text-pending" : "text-fg"}
                  />
                </dl>
                <p className="max-w-[96ch] text-[10px] leading-relaxed text-dimmer">
                  The session is a record in the server&apos;s database, referenced by an opaque value in an HttpOnly
                  cookie. This page holds no session token and no role flag, so nothing here can be edited to widen what
                  the account may do.
                </p>
                <button
                  type="button"
                  className="self-start text-[10px] uppercase"
                  disabled={busy !== ""}
                  onClick={() => {
                    void logout().then(() => {
                      window.location.assign("/");
                    });
                  }}
                >
                  [ SIGN OUT ]
                </button>
              </div>
            </Section>
          </>
        )}
      </main>

      <footer className="flex shrink-0 flex-col gap-1 border-t border-line bg-panel px-3 py-2 text-[10px] leading-relaxed text-dimmer">
        <span>
          Every value on this page was computed server-side after the caller&apos;s role was re-derived from the session
          record. No request made by this page may name a role or an owner for itself.
        </span>
        <span>
          A refusal is shown as a refusal with the server&apos;s own wording, and is never rendered as an empty table.
        </span>
      </footer>
    </div>
  );
}
