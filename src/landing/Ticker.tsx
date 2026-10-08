/**
 * The capability ticker.
 *
 * One strip of ten claims, moving left forever behind two hard fades at the edges.
 *
 * The list is rendered twice, and that duplication is the mechanism rather than a mistake:
 * the animation translates the track by exactly -50%, so the second copy is already in the
 * position the first one vacates. The moment the two halves differ by so much as an item,
 * the loop stutters visibly — so both copies are the same array mapped through the same
 * markup, and there is nowhere for them to drift apart.
 *
 * The fades are siblings of the track, not children: they sit above it and neither one
 * scrolls with it.
 */
import type { JSX } from "react";
import { Ic } from "./icons";

/** Ten claims, in the order the original shipped them. Order is the sequence, not a set. */
const ITEMS: readonly string[] = [
  "MEMORY INTEGRITY · SHA-256",
  "OBREGISTERCALLBACKS HANDLE STRIPPING",
  "HEURISTIC PATTERN SCANNING",
  "ANTI-DEBUG · PEB / NTQUERY",
  "DYNAMIC ALLOWLIST",
  "ADAPTIVE HEURISTICS",
  "DIGITAL SIGNATURE VERIFICATION",
  "SERVER-SIDE VALIDATION",
  "IOCTL BRIDGE · 0x9C40",
  "BLOCK ≠ BAN",
];

/**
 * One copy of the list. Not exported: the ticker's correctness depends on there being exactly
 * two of these and on both being this function, so nothing outside should be able to render
 * a third or a variant.
 */
function Half(): JSX.Element {
  return (
    <div className="flex shrink-0 items-center">
      {ITEMS.map((item) => (
        <span key={item} className="flex items-center whitespace-nowrap">
          <span className="px-8 font-mono text-xs tracking-[0.3em] text-mist transition-colors hover:text-white">{item}</span>
          <Ic name="shield-half" strokeWidth={2.5} className="size-3 shrink-0 text-volt/70" />
        </span>
      ))}
    </div>
  );
}

export default function Ticker(): JSX.Element {
  return (
    <div className="relative border-y border-line bg-ink/60 py-5 backdrop-blur">
      <div className="flex w-max animate-marquee">
        <Half />
        <Half />
      </div>
      <div className="pointer-events-none absolute inset-y-0 left-0 w-32 bg-gradient-to-r from-abyss to-transparent" />
      <div className="pointer-events-none absolute inset-y-0 right-0 w-32 bg-gradient-to-l from-abyss to-transparent" />
    </div>
  );
}
