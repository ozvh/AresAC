/**
 * Subject examination.
 *
 * Two data sources, deliberately kept separate:
 *
 *  - the header block is read from the live snapshot the console already holds, so
 *    the verdict, ladder step and containment state shown here are the arbiter's
 *    current state and not a cached copy;
 *  - the evidence histogram is *fetched* from GET /v1/subject/<tag>, because the
 *    retained sample breakdown exists only in the arbiter's window. The console
 *    cannot derive it, and does not pretend to: if the fetch fails, this panel says
 *    so instead of rendering an empty table that reads like "no evidence".
 *
 * Operator actions are the only writes this console can perform. They are disabled
 * without a token, and the outcome is reported from the arbiter's response rather
 * than assumed.
 */
import { useEffect, useState, type JSX, type ReactNode } from "react";
import {
  CODE_LABEL,
  type EvidenceCode,
  type PublicSubject,
  type Role,
} from "@shared/protocol";
import { telemetry, useConsole } from "@/lib/store";
import {
  ROLE_RING_LABEL,
  STEP_LABEL,
  STEP_TEXT,
  VERDICT_GLYPH,
  VERDICT_LABEL,
  VERDICT_TEXT,
  ringsFor,
} from "@/lib/theme";
import { bar, duration, group12, padZero, score } from "@/lib/format";
import { hasOperatorToken, sendControl } from "@/lib/api";

/** Shape of GET /v1/subject/<tag>: the arbiter's retained samples for one subject. */
type SubjectEvidence = {
  subject: PublicSubject;
  codes: { c: EvidenceCode; n: number; max: number }[];
  roles: Record<Role, number>;
};

/**
 * Discriminated union with no optional members, so `exactOptionalPropertyTypes`
 * cannot be satisfied by an object that is half-initialised.
 */
type EvidenceState =
  | { phase: "idle" }
  | { phase: "loading" }
  | { phase: "error"; reason: string }
  | { phase: "ready"; data: SubjectEvidence };

/** Re-read cadence for the retained-sample breakdown while a subject is selected. */
const POLL_MS = 2_000;

const KEYS = "text-[10px] uppercase tracking-[0.12em] text-dimmer";
const VALUE = "text-[11px]";

function Line({ label, children }: { label: string; children: ReactNode }): JSX.Element {
  return (
    <div className="flex gap-2">
      <span className="w-[86px] shrink-0 text-dimmer">{label}</span>
      <span className="min-w-0 flex-1 text-fg">{children}</span>
    </div>
  );
}

export default function SubjectDetail(): JSX.Element {
  const state = useConsole();
  const selected = state.selected;
  const [evidence, setEvidence] = useState<EvidenceState>({ phase: "idle" });
  const [outcome, setOutcome] = useState("");
  const authorised = hasOperatorToken();

  useEffect(() => {
    if (selected === null) {
      setEvidence({ phase: "idle" });
      return;
    }
    const controller = new AbortController();
    setOutcome("");

    const load = async (first: boolean): Promise<void> => {
      if (first) setEvidence({ phase: "loading" });
      try {
        const res = await fetch(`/v1/subject/${selected}`, {
          signal: controller.signal,
          headers: { accept: "application/json" },
        });
        if (!res.ok) {
          setEvidence({ phase: "error", reason: `HTTP ${res.status}` });
          return;
        }
        const body = (await res.json()) as SubjectEvidence;
        setEvidence({ phase: "ready", data: body });
      } catch (error) {
        if (controller.signal.aborted) return;
        setEvidence({ phase: "error", reason: error instanceof Error ? error.message : "transport failure" });
      }
    };

    void load(true);
    const timer = window.setInterval(() => {
      void load(false);
    }, POLL_MS);

    return () => {
      controller.abort();
      window.clearInterval(timer);
    };
  }, [selected]);

  async function run(action: "RELEASE" | "FLAG"): Promise<void> {
    if (selected === null) return;
    const result = await sendControl(action === "RELEASE" ? { op: "RELEASE", su: selected } : { op: "FLAG", su: selected });
    const message = result.ok ? `APPLIED ${result.applied}` : `REFUSED ${result.reason}`;
    setOutcome(message);
    telemetry.notify(message);
  }

  // Live row for the selected subject, taken from the snapshot already in hand.
  const live = selected === null ? undefined : state.subjects.find((subject) => subject.su === selected);
  const corroborating = live === undefined ? [] : ringsFor(live.rm);

  return (
    <section className="flex shrink-0 flex-col border-b border-line bg-panel">
      <header className="flex h-[22px] shrink-0 items-center justify-between border-b border-line px-2 text-[10px] uppercase tracking-[0.18em]">
        <span className="text-fg">SUBJECT EXAMINATION</span>
        <span className="text-dimmer">{selected === null ? "NO SELECTION" : "LIVE + FETCHED"}</span>
      </header>

      <div className="flex flex-col gap-3 p-2">
        {selected === null || live === undefined ? (
          <p className="text-[11px] leading-relaxed text-dimmer">
            {selected === null
              ? "select a subject in the tracked-subject ledger."
              : `subject ${selected} is no longer held by the arbiter: it fell outside the retention window or was released.`}
            <br />
            This panel renders two things and says which is which. The verdict block is read from the live snapshot. The
            retained-sample breakdown below it is fetched from the arbiter on demand, because a subject's evidence
            window exists only inside the arbiter — it is never reconstructed in the browser.
          </p>
        ) : (
          <>
            <div className="border border-line p-2">
              <div className={`${KEYS} mb-2 flex items-center justify-between`}>
                <span>VERDICT BLOCK · LIVE SNAPSHOT</span>
                <span className="num text-dimmer">{group12(live.su)}</span>
              </div>
              <div className="flex flex-col gap-1 leading-none">
                <Line label="SUBJECT">
                  <span className="num text-fg">{live.su}</span>
                </Line>
                <Line label="VERDICT">
                  <span className={VERDICT_TEXT[live.vd]}>
                    {VERDICT_GLYPH[live.vd]} {VERDICT_LABEL[live.vd]}
                  </span>
                </Line>
                <Line label="LADDER">
                  <span className={STEP_TEXT[live.st]}>{STEP_LABEL[live.st]}</span>
                </Line>
                <Line label="SCORE">
                  <span className="num text-fg">{score(live.sc)}</span>{" "}
                  <span className="text-dimmer">{bar(live.sc, 20)}</span>
                </Line>
                <Line label="DWELL">
                  <span className="num text-dim">{duration(live.dw)}</span>
                  <span className="text-dimmer"> sustained at or above the conviction threshold</span>
                </Line>
                <Line label="CORROB.">
                  {corroborating.length === 0 ? (
                    <span className="text-dimmer">NONE — no ring is corroborating</span>
                  ) : (
                    <span className="text-fg">
                      {corroborating.map((role) => ROLE_RING_LABEL[role]).join(" + ")}
                    </span>
                  )}
                </Line>
                <Line label="SAMPLES">
                  <span className="num text-dim">{padZero(live.n, 3)}</span>
                  <span className="text-dimmer"> retained inside the corroboration window</span>
                </Line>
                <Line label="CONTAINMENT">
                  {live.ct ? (
                    <span className="text-fg">
                      CAPABILITY DENIED — handle rights stripped or vetoed. No account action is implied by this line.
                    </span>
                  ) : (
                    <span className="text-dimmer">NO CAPABILITY RESTRICTION APPLIED</span>
                  )}
                </Line>
              </div>
            </div>

            <div className="border border-line p-2">
              <div className={`${KEYS} mb-2 flex items-center justify-between`}>
                <span>EVIDENCE LEDGER · FETCHED</span>
                <span className="num text-dimmer">GET /v1/subject/{live.su}</span>
              </div>

              {evidence.phase === "loading" ? (
                <p className={`${VALUE} text-dimmer`}>request in flight…</p>
              ) : evidence.phase === "error" ? (
                <p className={`${VALUE} text-flagged`}>
                  EVIDENCE UNAVAILABLE — {evidence.reason}. An empty table here would read as &quot;no evidence
                  retained&quot;, which this console must not imply.
                </p>
              ) : evidence.phase === "ready" ? (
                <div className="flex flex-col gap-1">
                  {evidence.data.codes.length === 0 ? (
                    <p className={`${VALUE} text-dimmer`}>
                      arbiter retains no samples for this subject inside the window.
                    </p>
                  ) : (
                    evidence.data.codes.map((row) => (
                      <div key={row.c} className="grid grid-cols-[20px_150px_34px_96px] items-center gap-x-2">
                        <span className="num text-dim">{row.c}</span>
                        <span className={`${VALUE} truncate text-fg`} title={CODE_LABEL[row.c]}>
                          {CODE_LABEL[row.c]}
                        </span>
                        <span className="num text-[11px] text-dim">{padZero(row.n, 3)}</span>
                        <span className="flex items-center gap-1">
                          <span className="num w-5 text-right text-[11px] text-dim">{padZero(row.max, 2)}</span>
                          <span className="text-dimmer">{bar(row.max / 100, 8)}</span>
                        </span>
                      </div>
                    ))
                  )}
                  <div className="mt-1 flex gap-3 border-t border-line pt-1 text-[10px] uppercase tracking-[0.12em] text-dimmer">
                    <span>BY RING</span>
                    <span>
                      R0 <span className="num text-dim">{padZero(evidence.data.roles.KMOD, 3)}</span>
                    </span>
                    <span>
                      R3 <span className="num text-dim">{padZero(evidence.data.roles.UMON, 3)}</span>
                    </span>
                    <span>
                      EXT <span className="num text-dim">{padZero(evidence.data.roles.SRV, 3)}</span>
                    </span>
                  </div>
                </div>
              ) : (
                <p className={`${VALUE} text-dimmer`}>awaiting selection…</p>
              )}
            </div>

            <div className="border border-line p-2">
              <div className={`${KEYS} mb-2`}>OPERATOR AUTHORITY</div>
              <div className="flex flex-wrap items-center gap-2">
                <button
                  type="button"
                  className="text-[10px] uppercase tracking-[0.12em]"
                  disabled={!authorised}
                  onClick={() => {
                    void run("RELEASE");
                  }}
                >
                  [ RELEASE ]
                </button>
                <button
                  type="button"
                  className="text-[10px] uppercase tracking-[0.12em]"
                  disabled={!authorised}
                  onClick={() => {
                    void run("FLAG");
                  }}
                >
                  [ FLAG ]
                </button>
                {authorised ? (
                  <span className="text-[10px] uppercase tracking-[0.12em] text-dimmer">
                    sealed into the hash chain
                  </span>
                ) : (
                  <span className="text-[10px] uppercase tracking-[0.12em] text-dimmer">operator token required</span>
                )}
              </div>
              {outcome !== "" && (
                <p className={`mt-2 ${VALUE} ${outcome.startsWith("APPLIED") ? "text-fg" : "text-flagged"}`}>
                  {outcome}
                </p>
              )}
            </div>
          </>
        )}
      </div>
    </section>
  );
}
