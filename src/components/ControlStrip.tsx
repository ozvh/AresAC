/**
 * Operator control plane.
 *
 * System-scoped authority only: pause, fleet rate, adversary profiles. Subject-scoped
 * actions (release, flag) belong to the subject detail panel, because they must be
 * taken while looking at the evidence they act on.
 *
 * Nothing here reports success before the arbiter has said so. Each action awaits its
 * own round trip and states the arbiter's answer verbatim — a control plane that
 * optimistically renders "PAUSED" while the arbiter keeps ingesting would be worse
 * than having no control plane at all.
 */
import { useState, type JSX } from "react";
import { SCENARIOS, type ControlAction, type ScenarioName } from "@shared/protocol";
import { hasOperatorToken, operatorToken, sendControl, setOperatorToken, type ControlOutcome } from "@/lib/api";
import { useConsole, telemetry } from "@/lib/store";
import { compact, pad } from "@/lib/format";

/** What each adversary profile is meant to exercise. The claim is the test. */
const SCENARIO_NOTE: Readonly<Record<ScenarioName, string>> = {
  AIMBOT_ONLY: "external behavioural signal only — must never convict",
  KERNEL_CHEAT: "structural evidence from two rings — must convict",
  OVERLAY_NOISE: "signed overlay traffic — must never leave CLEAN",
  SPOOF_ATTEMPT: "forged ring claim and replayed sequence — refused before adjudication",
  CAPACITY: "sustained flood — must be rate-limited without dropping the fleet",
};

const MAX_RATE = 200_000;

function describe(result: ControlOutcome): string {
  return result.ok ? `OK ${result.applied}` : `REFUSED ${result.reason}`;
}

export default function ControlStrip(): JSX.Element {
  const state = useConsole();
  const [draft, setDraft] = useState<string>(() => operatorToken());
  const [authorised, setAuthorised] = useState<boolean>(() => hasOperatorToken());
  const [outcome, setOutcome] = useState<string>("—");
  const [busy, setBusy] = useState<string | null>(null);
  const [rateDraft, setRateDraft] = useState<string>("");

  const run = async (action: ControlAction, label: string): Promise<void> => {
    if (busy !== null) return;
    setBusy(label);
    const result = await sendControl(action);
    const text = describe(result);
    setOutcome(text);
    telemetry.notify(text);
    setBusy(null);
  };

  const commitToken = (next: string): void => {
    setDraft(next);
    setOperatorToken(next);
    setAuthorised(hasOperatorToken());
  };

  const applyRate = (): void => {
    const parsed = Number(rateDraft.trim());
    if (rateDraft.trim() === "" || !Number.isFinite(parsed) || parsed < 0 || parsed > MAX_RATE) {
      const text = `REFUSED local: rate must be an integer in 0..${MAX_RATE}`;
      setOutcome(text);
      telemetry.notify(text);
      return;
    }
    void run({ op: "RATE", tps: Math.floor(parsed) }, "RATE");
  };

  const locked = !authorised || busy !== null;

  return (
    <section className="flex shrink-0 flex-col border-b border-line bg-panel">
      <header className="flex h-[22px] shrink-0 items-center justify-between border-b border-line px-2 text-[10px] uppercase tracking-[0.18em]">
        <span className="text-fg">OPERATOR CONTROL PLANE</span>
        <span className={authorised ? "text-fg" : "text-dimmer"}>
          {authorised ? "AUTHORISED" : "READ-ONLY"}
        </span>
      </header>

      <div className="flex flex-col gap-3 p-2">
        {/* ---------- credential ---------- */}
        <div className="flex flex-col gap-1">
          <span className="text-[10px] uppercase tracking-[0.12em] text-dimmer">OPERATOR TOKEN</span>
          <div className="flex items-center gap-2">
            <input
              type="password"
              value={draft}
              spellCheck={false}
              autoComplete="off"
              aria-label="operator token"
              className="num w-[196px] shrink-0 text-[11px]"
              onChange={(event) => commitToken(event.currentTarget.value)}
            />
            <button
              type="button"
              className="text-[10px] uppercase"
              onClick={() => commitToken("")}
              disabled={draft.length === 0}
            >
              [ CLEAR ]
            </button>
          </div>
          <p className="text-[10px] leading-relaxed text-dimmer">
            Every mutation is refused by the arbiter without this token. It is held in memory for this view only —
            never a cookie, a URL, or browser storage — so a reload asks for it again.
          </p>
        </div>

        {/* ---------- fleet actions ---------- */}
        <div className="flex flex-col gap-2 border-t border-line pt-2">
          <span className="text-[10px] uppercase tracking-[0.12em] text-dimmer">FLEET</span>
          <div className="flex items-center gap-2">
            <button
              type="button"
              className="flex-1 text-[10px] uppercase"
              disabled={locked || state.paused}
              onClick={() => void run({ op: "PAUSE" }, "PAUSE")}
            >
              [ PAUSE ]
            </button>
            <button
              type="button"
              className="flex-1 text-[10px] uppercase"
              disabled={locked || !state.paused}
              onClick={() => void run({ op: "RESUME" }, "RESUME")}
            >
              [ RESUME ]
            </button>
          </div>
          <div className="flex items-center gap-2">
            <span className="text-[10px] uppercase tracking-[0.12em] text-dimmer">TARGET EVT/S</span>
            <input
              type="text"
              inputMode="numeric"
              value={rateDraft}
              spellCheck={false}
              aria-label="fleet emission target, events per second"
              placeholder={String(state.rate)}
              className="num w-[72px] shrink-0 text-[11px]"
              onChange={(event) => setRateDraft(event.currentTarget.value.replace(/[^0-9]/g, ""))}
            />
            <button type="button" className="text-[10px] uppercase" disabled={locked} onClick={applyRate}>
              [ APPLY ]
            </button>
          </div>
        </div>

        {/* ---------- adversary profiles ---------- */}
        <div className="flex flex-col gap-1 border-t border-line pt-2">
          <span className="text-[10px] uppercase tracking-[0.12em] text-dimmer">ADVERSARY PROFILES · 20s</span>
          {SCENARIOS.map((name) => (
            <button
              key={name}
              type="button"
              className="flex w-full flex-col items-start gap-0.5 px-2 py-1 text-left"
              disabled={locked}
              onClick={() => void run({ op: "SCENARIO", name }, name)}
            >
              <span className="text-[10px] uppercase tracking-[0.14em] text-fg">{name}</span>
              <span className="text-[10px] leading-snug text-dimmer">{SCENARIO_NOTE[name]}</span>
            </button>
          ))}
        </div>

        {/* ---------- state readout ---------- */}
        <div className="flex flex-col gap-1 border-t border-line pt-2 text-[10px]">
          <span className="text-[10px] uppercase tracking-[0.12em] text-dimmer">LAST ARBITER ANSWER</span>
          <span className="num break-all text-dim">{outcome}</span>
          <dl className="grid grid-cols-[92px_minmax(0,1fr)] gap-x-2 text-dim">
            <dt className="text-dimmer">ARBITER PAUSED</dt>
            <dd className="num">{state.paused ? "TRUE" : "FALSE"}</dd>
            <dt className="text-dimmer">ARMED PROFILE</dt>
            <dd>{state.scenario === null ? "NONE" : state.scenario}</dd>
            <dt className="text-dimmer">RATE TARGET</dt>
            <dd className="num">{pad(state.rate, 6)} evt/s</dd>
            <dt className="text-dimmer">ACCEPTED</dt>
            <dd className="num">{state.counters === null ? "—" : compact(state.counters.rx)}</dd>
            <dt className="text-dimmer">PENDING CMDS</dt>
            <dd>{busy === null ? "NONE" : busy}</dd>
          </dl>
          <p className="leading-relaxed text-dimmer">
            A mutation is a change to engine behaviour, so the arbiter admits at most one every 250ms per operator
            and answers 429 to the rest.
          </p>
        </div>
      </div>
    </section>
  );
}
