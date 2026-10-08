/**
 * Section 03 — the adjudication pipeline.
 *
 * Four gates climb a vertical spine on the left, and a sticky plaque tracks the scroll on
 * the right. The section's whole argument is in the shape of the markup: the spine is drawn
 * once behind the cards, so it reads as one continuous pipeline rather than as four
 * unrelated panels, and each card carries its own decision branch — what happens when the
 * gate says NO, MATCH or THREAT — hanging off the bottom of its body copy.
 *
 * The four cards are one implementation fed by the GATES table. They differ only in copy,
 * glyph and branch colour, and four near-identical blocks of markup would have to be kept in
 * step by hand; a table cannot drift from itself.
 *
 * Colour here carries meaning and nothing else: blood is a refusal, mint is a pass, bolt is a
 * graded middle. That is why the branch accents live in a lookup of complete class strings —
 * Tailwind reads source statically, so an interpolated class name would never be generated.
 */
import type { JSX } from "react";
import { Ic } from "./icons";
import type { IconName } from "./icons";
import { Reveal } from "./Reveal";

/** The three verdict colours the branch blocks may use, and nothing else. */
type Accent = "blood" | "mint" | "bolt";

/**
 * One accent, three class groups.
 *
 * Every string is written out in full rather than assembled from the accent name, because
 * Tailwind's scanner only sees literals: `text-${accent}` would compile to no CSS at all.
 */
const ACCENT: Record<Accent, { readonly block: string; readonly arrow: string; readonly decision: string }> = {
  blood: {
    block: "border-l-2 p-4 border-blood/40 bg-blood/[0.07]",
    arrow: "h-3.5 w-3.5 text-blood",
    decision: "font-semibold text-blood",
  },
  mint: {
    block: "border-l-2 p-4 border-mint/40 bg-mint/[0.07]",
    arrow: "h-3.5 w-3.5 text-mint",
    decision: "font-semibold text-mint",
  },
  bolt: {
    block: "border-l-2 p-4 border-bolt/40 bg-bolt/[0.07]",
    arrow: "h-3.5 w-3.5 text-bolt",
    decision: "font-semibold text-bolt",
  },
};

/** A decision a gate can reach, and where it sends the event. */
interface Branch {
  /** The condition being tested, as the card labels it: NO, MATCH, THREAT, BENIGN. */
  readonly verdict: string;
  readonly accent: Accent;
  readonly decision: string;
  readonly detail: string;
}

interface Gate {
  readonly icon: IconName;
  /** SENSOR for the first card, GATE 01..03 for the rest. */
  readonly kicker: string;
  readonly meta: string;
  readonly title: string;
  readonly body: string;
  readonly branches: readonly Branch[];
  /**
   * The pass-through row, where a gate hands the event upward. `null` on the last gate: there
   * is nothing after certainty, and a "next gate" row there would be a lie.
   */
  readonly next: string | null;
}

const GATES: readonly Gate[] = [
  {
    icon: "radar",
    kicker: "SENSOR",
    meta: "ObCallback · PsNotify · ImageLoad",
    title: "SYSTEM EVENT CAUGHT",
    body:
      "A kernel callback fires: a process requested a handle to the game, mapped a section into it, or loaded an image into its address space. Nothing yet is assumed.",
    branches: [],
    next: null,
  },
  {
    icon: "file-badge",
    kicker: "GATE 01",
    meta: "authenticode · chain-of-trust",
    title: "IS THE BINARY DIGITALLY SIGNED?",
    body:
      "The driver parses the file's signing certificate and walks the chain to a trusted root. Code signed by Microsoft, NVIDIA, or Valve never even reaches the heuristic layer.",
    branches: [
      {
        verdict: "NO",
        accent: "blood",
        decision: "FLAG / CONTAIN",
        detail:
          "Unsigned code inherits zero trust: the handle is vetoed, the load is denied, telemetry escalates. The user notices nothing.",
      },
    ],
    next: "YES",
  },
  {
    icon: "list-checks",
    kicker: "GATE 02",
    meta: "SHA-256 corpus · fleet-synced · 90 s TTL",
    title: "CROSS-REFERENCE THE ALLOWLIST",
    body:
      "The signed binary's hash is matched against the live, server-synced allowlist of known-good overlays, capture suites and system components.",
    branches: [
      {
        verdict: "MATCH",
        accent: "mint",
        decision: "ALLOW EXECUTION",
        detail:
          "Alert suppressed before it is even logged as a candidate. Discord, OBS and GeForce overlays pass with zero friction.",
      },
    ],
    next: "NO MATCH",
  },
  {
    icon: "gauge",
    kicker: "GATE 03",
    meta: "behavioral scoring · time-windowed model",
    title: "ADAPTIVE HEURISTICS ENGAGE",
    body:
      "Unknown and unlisted: the model scores behavior across time — read cadence, timing deltas, injection patterns — and only crosses the conviction line when certainty is mathematical, not statistical luck.",
    branches: [
      {
        verdict: "THREAT",
        accent: "bolt",
        decision: "GRADED VERDICT",
        detail: "Capability blocked silently first; account action only after server corroboration. Block ≠ Ban.",
      },
      {
        verdict: "BENIGN",
        accent: "mint",
        decision: "ALLOW + LEARN",
        detail: "The pattern feeds the allowlist corpus — tomorrow this gate costs zero milliseconds.",
      },
    ],
    next: null,
  },
];

/** The plaque's three closing figures. */
const PANEL_STATS: readonly { readonly value: string; readonly label: string }[] = [
  { value: "3.0", label: "median gates to verdict" },
  { value: "34 ms", label: "avg adjudication time" },
  { value: "0.001%", label: "overturned on review" },
];

export default function Adjudication(): JSX.Element {
  return (
    <section id="adjudication" className="relative border-y border-line bg-ink/40">
      <div className="mx-auto max-w-[1440px] px-6 py-28 md:px-10 md:py-40">
        <Reveal className="mb-14 md:mb-20">
          <div className="flex items-center gap-4">
            <span className="font-mono text-[11px] tracking-[0.35em] text-volt">[03]</span>
            <span className="h-px w-10 bg-volt/50" />
            <span className="font-mono text-[11px] uppercase tracking-[0.35em] text-mist">Adjudication Pipeline</span>
          </div>
          <h2 className="mt-6 max-w-4xl font-display text-4xl font-semibold leading-[1.04] tracking-tight text-white md:text-6xl">
            Suspicion is cheap. <span className="text-hollow-volt">Proof is the product.</span>
          </h2>
          <p className="mt-6 max-w-xl text-base leading-relaxed text-mist md:text-lg">
            Every event climbs three structural gates before a player is touched — certificate first, corpus second,
            behavior last. Behavioral guesses never skip the queue.
          </p>
        </Reveal>

        <div className="grid gap-14 lg:grid-cols-[1fr_360px] xl:grid-cols-[1fr_400px]">
          <div className="relative">
            {/* The spine: one hairline behind all four cards, with a single pulse travelling it. */}
            <div className="absolute bottom-2 left-[23px] top-2 w-px bg-gradient-to-b from-volt/50 via-line-2 to-bolt/40" />
            <span className="spine-pulse absolute left-[20px] h-2 w-2 rounded-full bg-volt shadow-[0_0_16px_rgba(239,121,94,1)]" />

            <div className="flex flex-col gap-10">
              {GATES.map((gate) => (
                <Reveal key={gate.title} className="relative flex gap-5 md:gap-7">
                  <div className="relative z-10 flex w-12 shrink-0 justify-center">
                    <span className="grid h-12 w-12 place-items-center border border-line-2 bg-ink text-volt clip-notch">
                      <Ic name={gate.icon} strokeWidth={1.8} className="h-5 w-5" />
                    </span>
                  </div>

                  <div className="panel min-w-0 flex-1 p-6 md:p-8">
                    <div className="flex flex-wrap items-center gap-x-4 gap-y-2">
                      <span className="font-mono text-[10px] tracking-[0.34em] text-volt">{gate.kicker}</span>
                      <span className="font-mono text-[10px] tracking-[0.14em] text-mist/60">{gate.meta}</span>
                    </div>
                    <h3 className="mt-3 font-display text-xl font-bold tracking-wide text-white md:text-2xl">
                      {gate.title}
                    </h3>
                    <p className="mt-3 max-w-2xl text-sm leading-relaxed text-mist">{gate.body}</p>

                    {gate.branches.length > 0 || gate.next !== null ? (
                      <div className="mt-6 flex flex-col gap-3">
                        {gate.branches.map((branch) => (
                          <div key={branch.verdict} className={ACCENT[branch.accent].block}>
                            <div className="flex flex-wrap items-center gap-3 font-mono text-[11px] tracking-[0.18em]">
                              <span className="border border-line-2 px-2.5 py-1 text-mist">{branch.verdict}</span>
                              <Ic name="arrow-right" className={ACCENT[branch.accent].arrow} />
                              <span className={ACCENT[branch.accent].decision}>{branch.decision}</span>
                            </div>
                            <p className="mt-2.5 text-xs leading-relaxed text-mist/90">{branch.detail}</p>
                          </div>
                        ))}

                        {gate.next !== null ? (
                          <div className="flex items-center gap-3 font-mono text-[11px] tracking-[0.18em] text-mist">
                            <span className="border border-dashed border-line-2 px-2.5 py-1">{gate.next}</span>
                            <Ic name="arrow-down" className="h-3.5 w-3.5 text-volt" />
                            <span className="text-volt">NEXT GATE</span>
                            <span className="h-px flex-1 bg-line" />
                          </div>
                        ) : null}
                      </div>
                    ) : null}
                  </div>
                </Reveal>
              ))}
            </div>
          </div>

          {/* Sticky by intent, not by accident: the plaque is the section's thesis, and it
              stays in view while the gates scroll past it. It collapses to the end of the
              column below `lg`, where there is no room to track anything. */}
          <Reveal className="lg:sticky lg:top-28 lg:self-start">
            <div className="panel overflow-hidden">
              <div className="relative">
                <img
                  alt="Ares helmet emblem in bronze and crimson"
                  className="h-[420px] w-full object-cover object-top [mask-image:linear-gradient(to_bottom,black_55%,transparent_98%)]"
                  src="/images/ares-helmet.svg"
                />
                <span className="pointer-events-none absolute inset-x-0 top-0 h-full animate-scanline bg-gradient-to-b from-transparent via-volt/[0.08] to-transparent" />
                <div className="absolute left-5 top-5 flex items-center gap-2 border border-line bg-abyss/70 px-3 py-1.5 font-mono text-[10px] tracking-[0.28em] text-volt backdrop-blur">
                  <Ic name="scale" className="h-3.5 w-3.5" /> THE ADJUDICATOR
                </div>
                <div className="absolute bottom-3 left-5 right-5">
                  <p className="font-display text-2xl font-bold leading-tight text-white">
                    The burden of proof is on the machine.
                  </p>
                  <p className="mt-2 text-sm leading-relaxed text-mist">
                    Every false positive is a player executed by accident. ARES holds itself to a courtroom standard —
                    or it doesn't act.
                  </p>
                </div>
              </div>

              <div className="grid grid-cols-3 divide-x divide-line border-t border-line">
                {PANEL_STATS.map((stat) => (
                  <div key={stat.label} className="p-4 text-center">
                    <div className="font-display text-lg font-semibold text-volt tabular-nums md:text-xl">
                      {stat.value}
                    </div>
                    <div className="mt-1 font-mono text-[9px] uppercase leading-snug tracking-[0.16em] text-mist">
                      {stat.label}
                    </div>
                  </div>
                ))}
              </div>
            </div>
          </Reveal>
        </div>
      </div>
    </section>
  );
}
