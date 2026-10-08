/**
 * Adjudication gates.
 *
 * The arbiter resolves every sample at exactly one pipeline stage. `seen` is the
 * count of samples whose disposition was decided at that stage, so the distribution
 * between gates shows where the defence is actually spending its decisions — a
 * detector whose G1 column never moves is not verifying code identity at all.
 *
 * Nothing here is an estimate: the counters come from the arbiter, and the console
 * cannot influence them.
 */
import type { JSX } from "react";
import type { GateId } from "@shared/protocol";
import { useConsole } from "@/lib/store";
import { GATE_DESCRIPTION, GATE_ORDER } from "@/lib/theme";
import { bar, compact, pad } from "@/lib/format";

type Stage = { readonly gate: GateId; readonly label: string; readonly seen: number };

export default function GatePipeline(): JSX.Element {
  const state = useConsole();

  const stages: readonly Stage[] = GATE_ORDER.map((gate) => {
    const live = state.gates.find((entry) => entry.gate === gate);
    return { gate, label: live?.label ?? gate, seen: live?.seen ?? 0 };
  });

  const total = stages.reduce((sum, stage) => sum + stage.seen, 0);
  const awaiting = state.gates.length === 0;

  return (
    <section className="flex shrink-0 flex-col border-b border-line bg-panel">
      <header className="flex h-[22px] shrink-0 items-center justify-between border-b border-line px-2 text-[10px] uppercase tracking-[0.18em]">
        <span className="text-fg">ADJUDICATION GATES</span>
        <span className="text-dimmer">{compact(total)} RESOLVED</span>
      </header>

      <div className="p-2">
        {awaiting && <p className="mb-2 text-[10px] text-dimmer">AWAITING SNAPSHOT</p>}

        {stages.map((stage) => {
          const share = total === 0 ? 0 : stage.seen / total;
          return (
            <div key={stage.gate} className="mb-1.5 flex items-start gap-2 last:mb-0">
              <span className="num w-4 shrink-0 pt-px text-[10px] text-dim">{stage.gate}</span>
              <div className="min-w-0 flex-1">
                <div className="flex items-baseline justify-between">
                  <span className="text-[10px] uppercase tracking-[0.14em] text-fg">{stage.label}</span>
                  <span className="num text-[10px] text-dim">{pad(stage.seen, 7)}</span>
                </div>
                <div className="num text-[11px] text-dim">{bar(share, 22)}</div>
                <p className="text-[10px] leading-snug text-dimmer">{GATE_DESCRIPTION[stage.gate]}</p>
              </div>
            </div>
          );
        })}

        <div className="mt-2 border-t border-line pt-1.5">
          <p className="text-[10px] leading-snug text-dimmer">
            G1 decides binary identity, G2 decides membership of the fleet allowlist, G3 scores behaviour over a
            time window. Behavioural evidence never skips the queue: it is retained and scored, but it cannot
            discharge either of the two conviction paths on its own.
          </p>
          <p className="mt-1 text-[10px] leading-snug text-dimmer">
            A sample reaches G1 only after its MAC, schema, clock, sequence and ring provenance have all been
            accepted. Refused samples are counted in the rejection matrix, never scored here.
          </p>
        </div>
      </div>
    </section>
  );
}
