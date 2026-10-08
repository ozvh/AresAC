/**
 * Live thresholds.
 *
 * A read-only view of the arbiter's scoring model. Publishing these is deliberate:
 * the numbers are not secrets, and an operator who cannot see the threshold cannot
 * explain a decision. What is withheld is the evidence catalogue — severity,
 * classification and provenance per code stay server-side — so a fully
 * reverse-engineered console still cannot compute or mint a verdict of its own.
 */
import type { JSX } from "react";
import { useConsole } from "@/lib/store";
import { duration, pad, score } from "@/lib/format";

type Row = { readonly label: string; readonly value: string; readonly gloss: string };

export default function TuningPanel(): JSX.Element {
  const state = useConsole();
  const tuning = state.tuning;

  const rows: readonly Row[] =
    tuning === null
      ? []
      : [
          {
            label: "WINDOW",
            value: duration(tuning.windowMs),
            gloss: "evidence retention; samples older than this cannot corroborate",
          },
          {
            label: "SAMPLE CAP",
            value: pad(tuning.sampleCap, 5),
            gloss: "hard cap on retained samples per subject; oldest evicted first",
          },
          {
            label: "SUBJECT CAP",
            value: pad(tuning.subjectCap, 5),
            gloss: "hard cap on tracked subjects; least-recently-active evicted, flagged never evicted",
          },
          {
            label: "CONVICT SCORE",
            value: score(tuning.convictScore),
            gloss: "suspicion at or above which a subject is a conviction candidate",
          },
          {
            label: "PENDING SCORE",
            value: score(tuning.pendingScore),
            gloss: "suspicion at or above which a subject leaves CLEAN",
          },
          {
            label: "DWELL",
            value: duration(tuning.dwellMs),
            gloss: "time the suspicion must hold at the conviction score before a conviction issues",
          },
          {
            label: "DECAY AFTER",
            value: duration(tuning.decayMs),
            gloss: "idle time before suspicion begins decaying; a conviction is exempt",
          },
          {
            label: "VETO SCORE",
            value: score(tuning.vetoScore),
            gloss: "suspicion at or above which the ladder reaches capability denial",
          },
          {
            label: "RATE / AGENT",
            value: `${pad(tuning.ratePerSec, 4)}/s`,
            gloss: "sustained samples accepted per authenticated agent",
          },
          {
            label: "BURST",
            value: pad(tuning.rateBurst, 5),
            gloss: "bucket ceiling; a batch is charged for every sample it carries",
          },
          {
            label: "CLOCK SKEW",
            value: duration(tuning.maxSkewMs),
            gloss: "tolerance against the arbiter clock before a sample is refused as stale",
          },
        ];

  return (
    <section className="flex shrink-0 flex-col border-b border-line bg-panel">
      <header className="flex h-[22px] shrink-0 items-center justify-between border-b border-line px-2 text-[10px] uppercase tracking-[0.18em]">
        <span className="text-fg">LIVE THRESHOLDS</span>
        <span className="text-dimmer">{tuning === null ? "NO SNAPSHOT" : "SERVER-SOURCED"}</span>
      </header>

      <div className="p-2">
        {tuning === null ? (
          <p className="text-[10px] text-dimmer">AWAITING SNAPSHOT</p>
        ) : (
          <>
            <div className="text-[10px] leading-snug">
              {rows.map((row) => (
                <div key={row.label} className="border-b border-line py-1 last:border-b-0">
                  <div className="flex items-baseline justify-between gap-2">
                    <span className="shrink-0 text-[10px] uppercase tracking-[0.12em] text-dim">{row.label}</span>
                    <span className="num shrink-0 text-[10px] text-fg">{row.value}</span>
                  </div>
                  <p className="text-[10px] leading-snug text-dimmer">{row.gloss}</p>
                </div>
              ))}
            </div>
            <p className="mt-2 text-[10px] leading-snug text-dimmer">
              Served by the arbiter on each snapshot. The console holds no scoring table of its own: severity,
              classification and authorised reporting ring per evidence code exist only server-side, so a
              compromised console can forge a display but not a decision.
            </p>
          </>
        )}
      </div>
    </section>
  );
}
