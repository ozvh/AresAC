/**
 * Tracked subject ledger.
 *
 * One row per subject the arbiter is currently holding, in the arbiter's own order
 * (score descending — the console does not re-sort, because the ranking is a server
 * decision and re-deriving it here would let a display bug masquerade as a changed
 * verdict).
 *
 * The panel has a fixed body height. A ledger that grows as subjects arrive would
 * push the event stream around on every commit, so the height is constant and the
 * body scrolls.
 *
 * The arbiter caps this table at 120 subjects per snapshot, so the row count is
 * bounded by the server rather than by a layout guess and no windowing is needed.
 * Verdict colour is used only in the verdict column and in the flagged-count meta;
 * the selected row is marked with a glyph and a lighter ground, never with colour.
 */
import type { JSX } from "react";
import type { PublicSubject } from "@shared/protocol";
import { telemetry, useConsole } from "@/lib/store";
import { STEP_LABEL, STEP_TEXT, VERDICT_GLYPH, VERDICT_LABEL, VERDICT_TEXT, maskCells } from "@/lib/theme";
import { duration, padZero, score } from "@/lib/format";

/** Body height, exclusive of the panel header and the column-label row. */
const BODY_H = 248;

const GRID =
  "grid grid-cols-[12px_84px_72px_24px_34px_48px_84px_30px_40px_48px] items-center gap-x-2 px-2 text-[11px]";

function LedgerRow({ subject, selected }: { subject: PublicSubject; selected: boolean }): JSX.Element {
  const age = Date.now() - subject.last;
  return (
    <div
      role="button"
      tabIndex={0}
      aria-pressed={selected}
      onClick={() => telemetry.select(subject.su)}
      onKeyDown={(event) => {
        if (event.key === "Enter" || event.key === " ") {
          event.preventDefault();
          telemetry.select(subject.su);
        }
      }}
      className={`${GRID} row-h cursor-pointer whitespace-nowrap ${selected ? "bg-panel2" : "bg-transparent"}`}
    >
      <span className={selected ? "text-fg" : "text-dimmer"}>{selected ? ">" : "·"}</span>
      <span className="text-fg" title={subject.su}>
        {subject.su}
      </span>
      <span className={VERDICT_TEXT[subject.vd]}>
        {VERDICT_GLYPH[subject.vd]} {VERDICT_LABEL[subject.vd]}
      </span>
      <span className="text-dim" title="corroborating rings: R0 kernel, R3 user-mode, EXT server">
        {maskCells(subject.rm)}
      </span>
      <span className="num text-fg">{score(subject.sc)}</span>
      <span className="num text-dim">{duration(subject.dw)}</span>
      <span className={STEP_TEXT[subject.st]}>{STEP_LABEL[subject.st]}</span>
      <span className={subject.ct ? "text-fg" : "text-dimmer"} title="capability containment applied">
        {subject.ct ? "YES" : "NO"}
      </span>
      <span className="num text-dim">{padZero(subject.n, 3)}</span>
      <span className="num text-dimmer">{duration(age)}</span>
    </div>
  );
}

export default function SubjectLedger(): JSX.Element {
  const state = useConsole();

  let flagged = 0;
  let pending = 0;
  for (const subject of state.subjects) {
    if (subject.vd === "FLAGGED") flagged += 1;
    else if (subject.vd === "PENDING") pending += 1;
  }

  return (
    <section className="flex min-h-0 shrink-0 flex-col border-t border-line bg-panel">
      <header className="flex h-[22px] shrink-0 items-center justify-between border-b border-line px-2 text-[10px] uppercase tracking-[0.18em]">
        <span className="text-fg">TRACKED SUBJECTS</span>
        <span className="flex items-center gap-3 text-dimmer">
          <span>
            TRACKED <span className="num text-fg">{padZero(state.subjects.length, 3)}</span>
          </span>
          <span>
            FLAGGED <span className="num text-flagged">{padZero(flagged, 3)}</span>
          </span>
          <span>
            PENDING <span className="num text-pending">{padZero(pending, 3)}</span>
          </span>
        </span>
      </header>

      <div className={`${GRID} shrink-0 border-b border-line py-1 uppercase tracking-[0.12em] text-dimmer`}>
        <span />
        <span>SUBJECT</span>
        <span>VERDICT</span>
        <span>RINGS</span>
        <span>SCORE</span>
        <span>DWELL</span>
        <span>LADDER</span>
        <span>CONT</span>
        <span>SMP</span>
        <span>AGE</span>
      </div>

      <div className="overflow-y-scroll" style={{ height: BODY_H }}>
        {state.subjects.length === 0 ? (
          <p className="px-2 py-3 text-[11px] leading-relaxed text-dimmer">
            arbiter is tracking no subjects.
            <br />
            A subject enters this table only on a sample that arrived over an authenticated channel, passed schema
            validation, carried a strictly increasing sequence, and matched the ring provisioned to its agent. Nothing
            is created here by the console.
          </p>
        ) : (
          state.subjects.map((subject) => (
            <LedgerRow key={subject.su} subject={subject} selected={state.selected === subject.su} />
          ))
        )}
      </div>
    </section>
  );
}
