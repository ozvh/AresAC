/**
 * Refusal ledger.
 *
 * Every sample this arbiter refuses is refused upstream of the scoring path, so a
 * refused sample can never influence a verdict — it can only be counted. That makes
 * this table the honest measure of the perimeter: a rising SIG or ROLE column is a
 * generator attempting to impersonate a ring, and a rising RL column is a flood
 * being held at the token bucket rather than admitted and scored.
 *
 * Classes flagged critical take a state colour once their count is non-zero. Nothing
 * else in this panel is coloured.
 */
import type { JSX } from "react";
import { useConsole } from "@/lib/store";
import { REJECTION_CLASSES } from "@/lib/theme";
import { compact } from "@/lib/format";

const GRID = "grid grid-cols-[20px_46px_56px_minmax(0,1fr)] items-center gap-x-2 px-2";

export default function RejectionMatrix(): JSX.Element {
  const state = useConsole();
  const { counters } = state;

  const counts = REJECTION_CLASSES.map((cls) => (counters === null ? 0 : counters[cls.field]));
  const total = counts.reduce((sum, value) => sum + value, 0);

  return (
    <section className="flex shrink-0 flex-col border-b border-line bg-panel">
      <header className="flex h-[22px] shrink-0 items-center justify-between border-b border-line px-2 text-[10px] uppercase tracking-[0.18em]">
        <span className="text-fg">REFUSED BEFORE ADJUDICATION</span>
        <span className={`num ${total > 0 ? "text-fg" : "text-dimmer"}`}>
          {counters === null ? "—" : compact(total)}
        </span>
      </header>

      <div className={`${GRID} shrink-0 border-b border-line py-1 text-[10px] uppercase tracking-[0.12em] text-dimmer`}>
        <span>CLS</span>
        <span>CLASS</span>
        <span className="text-right">COUNT</span>
        <span>CAUSE</span>
      </div>

      <div className="flex flex-col">
        {REJECTION_CLASSES.map((cls, index) => {
          const count = counts[index] ?? 0;
          const critical = cls.critical && count > 0;
          return (
            <div key={cls.key} className={`${GRID} row-h`} title={cls.detail}>
              <span className="text-dimmer">{cls.critical ? "[!]" : "[-]"}</span>
              <span className="text-dim">{cls.label}</span>
              <span className={`num text-right ${critical ? "text-flagged" : count > 0 ? "text-fg" : "text-dimmer"}`}>
                {counters === null ? "—" : compact(count)}
              </span>
              <span className="truncate text-dimmer">{cls.detail}</span>
            </div>
          );
        })}
      </div>

      <footer className="border-t border-line px-2 py-1.5 text-[10px] leading-[1.5] text-dimmer">
        {counters === null
          ? "AWAITING SNAPSHOT"
          : `TOTAL ${compact(total)} REFUSED · ENFORCED IN transport -> schema -> MAC -> provenance -> velocity -> sequence -> clock ORDER, EVERY STAGE BEFORE SCORING`}
      </footer>
    </section>
  );
}
