/**
 * Chain of custody.
 *
 * The console is the only place an operator can see whether the arbiter's own record
 * of its irreversible decisions is still intact. Each sealed record carries the hash
 * of the record before it, so editing any historical verdict invalidates that record
 * and every record after it — which is exactly what this panel renders as CHAIN BROKEN.
 */
import type { JSX } from "react";
import type { LedgerView } from "@shared/protocol";
import { useConsole } from "@/lib/store";
import { clock } from "@/lib/format";

/** Records retained in the tail. The chain head survives eviction of older records. */
const MAX_ROWS = 48;

/**
 * Only two sealed kinds encode a verdict outcome, so only those two may carry state
 * colour: a conviction is flagged, a release restores clean. Containment changes and
 * control actions are decisions but not verdicts, and stay monochrome.
 */
function kindClass(record: LedgerView): string {
  if (record.kind === "VERDICT") return record.dt.startsWith("FLAGGED") ? "text-flagged" : "text-dim";
  if (record.kind === "RELEASE") return "text-clean";
  return "text-dim";
}

function LedgerRow({ record }: { record: LedgerView }): JSX.Element {
  return (
    <li className="flex h-[30px] flex-col justify-center border-b border-line px-2">
      <span className="flex items-baseline gap-2 text-[10px] whitespace-nowrap">
        <span className="num w-[42px] shrink-0 text-dimmer">#{String(record.seq).padStart(5, "0")}</span>
        <span className={`w-[54px] shrink-0 uppercase ${kindClass(record)}`}>{record.kind}</span>
        <span className="w-[64px] shrink-0 text-dim" title={record.su}>
          {record.su === "-" ? "—" : record.su.slice(0, 8)}
        </span>
        <span className="truncate text-fg" title={record.dt}>
          {record.dt}
        </span>
      </span>
      <span className="flex items-baseline gap-2 text-[10px] text-dimmer">
        <span className="num w-[72px] shrink-0">{clock(record.ts)}</span>
        <span className="num" title={record.h}>
          {record.h}
        </span>
      </span>
    </li>
  );
}

export default function IntegrityChain(): JSX.Element {
  const state = useConsole();
  const { chain } = state;
  const sealed = chain === null ? 0 : chain.sealed;
  const broken = chain !== null && chain.broken;

  // The ledger arrives oldest-first; the operator reads newest-first.
  const rows = state.ledger.slice(-MAX_ROWS).reverse();

  return (
    <section className="flex shrink-0 flex-col border-b border-line bg-panel">
      <header className="flex h-[22px] shrink-0 items-center justify-between border-b border-line px-2 text-[10px] uppercase tracking-[0.18em]">
        <span className="text-fg">CHAIN OF CUSTODY</span>
        <span className="num text-dimmer">{sealed} SEALED</span>
      </header>

      <div className="flex shrink-0 flex-col gap-1 border-b border-line p-2 text-[10px]">
        <span className={broken ? "text-flagged" : "text-fg"}>
          {broken ? "[!] CHAIN BROKEN" : "[+] CHAIN VERIFIED"}
        </span>
        <dl className="grid grid-cols-[76px_minmax(0,1fr)] gap-x-2 text-dim">
          <dt className="text-dimmer">HEAD</dt>
          <dd className="num truncate text-dimmer" title={chain === null ? "" : chain.head}>
            {chain === null ? "—" : chain.head.slice(0, 24)}
          </dd>
          <dt className="text-dimmer">RETAINED</dt>
          <dd className="num">{state.ledger.length}</dd>
          <dt className="text-dimmer">SEALED ALL</dt>
          <dd className="num">{sealed}</dd>
          <dt className="text-dimmer">BROKEN AT</dt>
          <dd className={broken ? "text-flagged" : "text-dim"}>
            {chain === null || chain.brokenAt === null ? "—" : `SEQ ${chain.brokenAt}`}
          </dd>
        </dl>
      </div>

      {/* Fixed height: the tail is a bounded read-out, not a window onto unbounded
          history, and a fixed box keeps the rail's geometry constant. */}
      <ul className="h-[210px] overflow-y-scroll">
        {rows.length === 0 ? (
          <li className="px-2 py-3 text-[11px] text-dimmer">
            awaiting snapshot · no sealed decision recorded yet
          </li>
        ) : (
          rows.map((record) => <LedgerRow key={record.seq} record={record} />)
        )}
      </ul>

      <footer className="flex shrink-0 flex-col gap-1 border-t border-line p-2 text-[10px] leading-relaxed text-dimmer">
        <span>
          Each record is sealed with the hash of the record before it, so retroactively editing any historical
          verdict invalidates that record and every record after it. The running head hash is kept even after old
          records are evicted from this tail, so tampering stays detectable past eviction.
        </span>
        <span>
          Sealed: verdict transitions, containment changes, operator releases and control actions. Raw evidence
          samples are not sealed here — they are evidence, not decisions.
        </span>
      </footer>
    </section>
  );
}
