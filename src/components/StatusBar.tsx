/**
 * System status bar.
 *
 * Three groups, left to right: the principal this console is bound to and the state
 * of that binding, the arbiter's own counters, then custody of the evidence chain and
 * the health of the stream carrying it. Every value is fixed width, so a counter
 * incrementing cannot move its neighbours.
 *
 * This bar is the only place a link state is permitted to take a state colour:
 * a dead uplink is a critical condition, which is exactly what those three colours
 * are reserved for.
 */
import type { JSX } from "react";
import { useConsole, type LinkState } from "@/lib/store";
import { compact, duration, uptime } from "@/lib/format";

/**
 * Adjudication latency arrives in microseconds. Reporting a sub-millisecond path in
 * whole milliseconds would round it to a flat zero and hide the property entirely.
 */
function latency(micros: number): string {
  return micros < 1000 ? `${micros}us` : `${(micros / 1000).toFixed(1)}ms`;
}

/** Link state -> colour class. Only DOWN and the transitional states take colour. */
const LINK_TEXT: Readonly<Record<LinkState, string>> = {
  IDLE: "text-dimmer",
  CONNECTING: "text-pending",
  LIVE: "text-fg",
  RESET: "text-pending",
  DOWN: "text-flagged",
};

function Cell({ label, value, tone = "text-fg" }: { label: string; value: string; tone?: string }): JSX.Element {
  return (
    <span className="flex items-baseline gap-1.5">
      <span className="text-dimmer">{label}</span>
      <span className={`num ${tone}`}>{value}</span>
    </span>
  );
}

export default function StatusBar(): JSX.Element {
  const state = useConsole();
  const { counters, chain } = state;

  const ingestAge = state.lastFrameAt === 0 ? "—" : duration(Date.now() - state.lastFrameAt);
  // The broken-chain flag is a critical state condition and the only reason this
  // group takes colour; the age and frame counters stay monochrome, because the
  // link token on the left already carries the critical signal.
  const chainTone = chain === null ? "text-dimmer" : chain.broken ? "text-flagged" : "text-fg";
  const chainStatus = chain === null ? "—" : chain.broken ? "BROKEN" : "OK";

  return (
    <header className="flex h-[30px] shrink-0 items-center justify-between gap-4 overflow-hidden border-b border-line bg-panel px-2 text-[10px] uppercase tracking-[0.18em]">
      {/* Principal and binding */}
      <span className="flex shrink-0 items-center gap-3">
        <span className="text-fg">ARES // ARBITER CONSOLE</span>
        <span className={LINK_TEXT[state.link]}>[{state.link}]</span>
        {state.reason === "" ? null : <span className="text-dimmer">· {state.reason}</span>}
        {/* The only navigation out of the console, and the only way the public
            request surface is reachable from the operator tool. Monochrome: it
            encodes no verdict, so it may not take a state colour. */}
        <a href="/request" className="text-dimmer hover:text-fg">
          REQUEST BUILD {"->"}
        </a>
      </span>

      {/* Arbiter counters */}
      <span className="flex min-w-0 flex-wrap items-baseline justify-center gap-x-3 gap-y-0">
        <Cell label="UPTIME" value={uptime(state.uptimeMs)} />
        <Cell label="AGENTS" value={String(state.agents)} />
        <Cell label="CORPUS" value={compact(state.corpus)} />
        <Cell
          label="SUBJ"
          value={counters === null ? "—" : String(counters.subj)}
          tone={counters !== null && counters.subj > 0 ? "text-fg" : "text-dimmer"}
        />
        <Cell label="EVT/S" value={counters === null ? "—" : String(counters.tps)} />
        <Cell label="ADJ p95" value={counters === null ? "—" : latency(counters.p95)} />
        <Cell label="ACCEPTED" value={counters === null ? "—" : compact(counters.rx)} />
        <Cell
          label="EVICTED"
          value={counters === null ? "—" : compact(counters.evicted)}
          tone={counters !== null && counters.evicted > 0 ? "text-fg" : "text-dimmer"}
        />
      </span>

      {/* Chain of custody and stream health */}
      <span className="flex shrink-0 items-baseline gap-3">
        <span className="flex items-baseline gap-1.5">
          <span className="text-dimmer">CHAIN</span>
          <span className="num text-fg">{chain === null ? "—" : String(chain.sealed)}</span>
          <span className="text-dimmer">SEALED</span>
          <span className="num text-dim">{chain === null ? "—" : chain.head.slice(0, 8)}</span>
          <span className={chainTone}>{chainStatus}</span>
        </span>
        <Cell label="INGEST AGE" value={ingestAge} tone="text-fg" />
        <Cell label="FRAMES" value={String(state.frames)} tone="text-dim" />
        <Cell label="RESETS" value={String(state.resets)} tone={state.resets > 0 ? "text-fg" : "text-dimmer"} />
      </span>
    </header>
  );
}
