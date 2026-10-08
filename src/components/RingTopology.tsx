/**
 * Corroboration topology.
 *
 * Shows what each reporting ring is actually contributing to the evidence pool, and
 * restates the conviction rule from the arbiter's own live thresholds so an operator
 * can see why a subject is PENDING rather than FLAGGED. The rule is not described
 * from memory: every number is read from `state.tuning`, which the arbiter serves.
 *
 * This panel is monochrome by design. Ring contribution is not a verdict, so it is
 * not permitted to borrow the state channel.
 */
import type { JSX } from "react";
import type { Role } from "@shared/protocol";
import { useConsole } from "@/lib/store";
import { ROLE_LONG, ROLE_RING_LABEL, ringCount } from "@/lib/theme";
import { bar, compact, duration, pad, score } from "@/lib/format";

const RING_ORDER: readonly Role[] = ["KMOD", "UMON", "SRV"];

/**
 * What each ring can and cannot observe. Stated as a capability boundary, because
 * the boundary is the reason three rings exist instead of one.
 */
const RING_VISIBILITY: Readonly<Record<Role, string>> = {
  KMOD:
    "observes handle creation, image loads, thread origin and process birth system-wide. Cannot interpret intent, and never dereferences third-party driver memory.",
  UMON:
    "observes loaded modules, injected threads and its own executable pages. Cannot see another process's memory, and cannot survive a kernel-level cheat.",
  SRV:
    "re-derives movement, hit registration and economy off-client. Observes nothing on the machine, and a single behavioural signal here is never sufficient to convict.",
};

type Bucket = { readonly label: string; readonly count: number };

function distribution(masks: readonly number[]): Bucket[] {
  let many = 0;
  let one = 0;
  let none = 0;
  for (const mask of masks) {
    const rings = ringCount(mask);
    if (rings >= 2) many += 1;
    else if (rings === 1) one += 1;
    else none += 1;
  }
  return [
    { label: "2+ RINGS CORROBORATE", count: many },
    { label: "SINGLE RING", count: one },
    { label: "NO CORROBORATION", count: none },
  ];
}

export default function RingTopology(): JSX.Element {
  const state = useConsole();
  const { counters, tuning } = state;

  const counts: Record<Role, number> = {
    KMOD: counters?.ring.KMOD ?? 0,
    UMON: counters?.ring.UMON ?? 0,
    SRV: counters?.ring.SRV ?? 0,
  };
  const total = counts.KMOD + counts.UMON + counts.SRV;

  const buckets = distribution(state.subjects.map((s) => s.rm));
  const tracked = state.subjects.length;

  return (
    <section className="flex shrink-0 flex-col border-b border-line bg-panel">
      <header className="flex h-[22px] shrink-0 items-center justify-between border-b border-line px-2 text-[10px] uppercase tracking-[0.18em]">
        <span className="text-fg">CORROBORATION TOPOLOGY</span>
        <span className="text-dimmer">{compact(total)} ADJUDICATED</span>
      </header>

      <div className="p-2">
        {RING_ORDER.map((role) => {
          const count = counts[role];
          const share = total === 0 ? 0 : count / total;
          return (
            <div key={role} className="mb-2 border border-line bg-panel2 px-2 py-1.5 last:mb-0">
              <div className="flex items-baseline justify-between">
                <span className="text-[10px] uppercase tracking-[0.16em] text-fg">
                  {ROLE_RING_LABEL[role]} · {ROLE_LONG[role]}
                </span>
                <span className="num text-[10px] text-dim">{compact(count)}</span>
              </div>
              <div className="num mt-0.5 text-[11px] text-dim">{bar(share, 24)}</div>
              <p className="mt-1 text-[10px] leading-snug text-dimmer">{RING_VISIBILITY[role]}</p>
            </div>
          );
        })}

        <div className="mt-2 border border-line px-2 py-1.5">
          <div className="text-[10px] uppercase tracking-[0.16em] text-dim">
            CONVICTION RULE · LIVE THRESHOLDS
          </div>
          {tuning === null ? (
            <p className="mt-1 text-[10px] text-dimmer">AWAITING SNAPSHOT</p>
          ) : (
            <ul className="mt-1 space-y-0.5 text-[10px] leading-snug text-dimmer">
              <li>
                <span className="text-dim">PATH A</span> two distinct rings corroborate (severity{" "}
                <span className="num text-dim">{tuning.corroborateSev}+</span>) and score{" "}
                <span className="num text-dim">{score(tuning.convictScore)}</span> holds for{" "}
                <span className="num text-dim">{duration(tuning.dwellMs)}</span>
              </li>
              <li>
                <span className="text-dim">PATH B</span> one structural proof at severity{" "}
                <span className="num text-dim">{tuning.structuralCertaintySev}+</span> — X1, X2 or X3 —
                corroborated by its ring, held for the same{" "}
                <span className="num text-dim">{duration(tuning.dwellMs)}</span>
              </li>
              <li>
                <span className="text-dim">CEILING</span> a single-ring behavioural signal holds a subject at
                PENDING indefinitely and can never reach a conviction, however high it scores
              </li>
              <li>
                <span className="text-dim">WINDOW</span> evidence older than{" "}
                <span className="num text-dim">{duration(tuning.windowMs)}</span> cannot corroborate anything; a
                subject idle beyond <span className="num text-dim">{duration(tuning.decayMs)}</span> decays, but a
                conviction never does
              </li>
            </ul>
          )}
        </div>

        <div className="mt-2 border border-line px-2 py-1.5">
          <div className="flex items-baseline justify-between">
            <span className="text-[10px] uppercase tracking-[0.16em] text-dim">CORROBORATION DEPTH</span>
            <span className="num text-[10px] text-dimmer">{pad(tracked, 3)} TRACKED</span>
          </div>
          {buckets.map((bucket) => {
            const share = tracked === 0 ? 0 : bucket.count / tracked;
            return (
              <div key={bucket.label} className="mt-1 flex items-center gap-2">
                <span className="w-[132px] shrink-0 text-[10px] text-dimmer">{bucket.label}</span>
                <span className="num text-[10px] text-dim">{bar(share, 12)}</span>
                <span className="num text-[10px] text-dim">{pad(bucket.count, 3)}</span>
              </div>
            );
          })}
          <p className="mt-1.5 text-[10px] leading-snug text-dimmer">
            Depth counts the distinct rings whose corroborating evidence is still inside the retention window.
            A subject's depth falls to zero as its evidence expires, not when a detector stops looking.
          </p>
        </div>
      </div>
    </section>
  );
}
