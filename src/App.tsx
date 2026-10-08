/**
 * Operator console shell.
 *
 * Layout is a fixed grid with an explicit minimum width. It does not reflow: an
 * operator reading a conviction ledger must not have the columns move underneath
 * them because a panel changed height. Below the minimum width the page scrolls
 * horizontally rather than rearranging itself.
 *
 * Panels do not scroll the document. Each owns its own overflow, so the shell's
 * geometry is constant for the whole session.
 */
import { useEffect, type JSX } from "react";
import StatusBar from "./components/StatusBar";
import EventStream from "./components/EventStream";
import SubjectLedger from "./components/SubjectLedger";
import SubjectDetail from "./components/SubjectDetail";
import RingTopology from "./components/RingTopology";
import GatePipeline from "./components/GatePipeline";
import RejectionMatrix from "./components/RejectionMatrix";
import TuningPanel from "./components/TuningPanel";
import IntegrityChain from "./components/IntegrityChain";
import ControlStrip from "./components/ControlStrip";
import { telemetry, useConsole } from "./lib/store";
import { duration } from "./lib/format";

/**
 * Operator log. The only region that reports the outcome of a deliberate operator
 * action, so a refused control command is never mistaken for a successful one.
 */
function OperatorLog(): JSX.Element {
  const state = useConsole();
  const ingestAge = state.lastFrameAt === 0 ? "—" : duration(Date.now() - state.lastFrameAt);
  return (
    <footer className="flex h-[20px] shrink-0 items-center justify-between gap-4 border-t border-line bg-panel px-2 text-[10px] uppercase tracking-[0.18em]">
      <span className={state.notice === "" ? "text-dimmer" : "text-fg"}>
        {state.notice === "" ? "OPERATOR LOG · NO COMMAND ISSUED THIS SESSION" : `OPERATOR LOG · ${state.notice}`}
      </span>
      <span className="flex shrink-0 items-baseline gap-3 text-dimmer">
        <span>
          SCENARIO <span className="text-dim">{state.scenario ?? "NONE"}</span>
        </span>
        <span>
          FLEET <span className="num text-dim">{state.rate}</span> EVT/S
        </span>
        <span>
          INGEST AGE <span className="num text-dim">{ingestAge}</span>
        </span>
        <span className={state.paused ? "text-pending" : "text-dim"}>
          {state.paused ? "ARBITER PAUSED" : "ARBITER ADMITTING"}
        </span>
      </span>
    </footer>
  );
}

export default function App(): JSX.Element {
  useEffect(() => {
    telemetry.start();
    return () => telemetry.stop();
  }, []);

  return (
    <div className="flex h-screen min-w-[1240px] flex-col overflow-hidden bg-void text-fg">
      <StatusBar />

      <div className="grid min-h-0 flex-1 grid-cols-[292px_minmax(0,1fr)_356px]">
        {/* Left rail: what the defence is made of, and how it is tuned. */}
        <div className="flex min-h-0 flex-col overflow-y-scroll bg-void">
          <RingTopology />
          <GatePipeline />
          <RejectionMatrix />
          <TuningPanel />
        </div>

        {/* Centre: the evidence firehose, and the subjects it implicates. */}
        <div className="flex min-h-0 flex-col border-x border-line bg-void">
          <EventStream />
          <SubjectLedger />
        </div>

        {/* Right rail: one subject in full, operator authority, chain of custody. */}
        <div className="flex min-h-0 flex-col overflow-y-scroll bg-void">
          <SubjectDetail />
          <ControlStrip />
          <IntegrityChain />
        </div>
      </div>

      <OperatorLog />
    </div>
  );
}
