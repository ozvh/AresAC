/**
 * The hero.
 *
 * A full-height statement in five stacked parts: the lightning canvas, the ring provenance
 * line, the ZEUS mark, the promise and its two calls to action, and the stat grid over a
 * fixed telemetry strip.
 *
 * Three details are load-bearing and easy to destroy by "tidying":
 *
 *  - ZEUS IS DRAWN THREE TIMES. The real `<h1>` is flanked by two absolutely positioned
 *    aria-hidden copies — one outlined in mist, one in volt — offset by fractions of an em.
 *    That stack is the depth in the mark; the offsets are in `em` so they scale with the
 *    clamp() font size instead of drifting apart on a narrow screen.
 *  - THE DECORATIVE COPIES ARE HIDDEN FROM THE ACCESSIBILITY TREE. `Reveal` animates the
 *    element it renders and takes no ARIA props, so the two copies are wrapped in a single
 *    `aria-hidden` span. The wrapper is inline and its children are out of flow, so it
 *    occupies no space and the absolutely positioned copies still resolve against the
 *    `relative` parent they were measured against.
 *  - THE CANVAS SIZES ITSELF. `HeroCanvas` measures its own box and multiplies by the device
 *    pixel ratio, so it takes a className and nothing else.
 */
import type { JSX } from "react";
import HeroCanvas from "./HeroCanvas";
import { Reveal } from "./Reveal";
import { Ic } from "./icons";

/**
 * The four numbers under the promise.
 *
 * `unit` is optional rather than empty-string, because "3 ENFORCEMENT RINGS" has no unit to
 * colour: the original emitted an empty `<span class="text-volt">` beside it, which renders
 * nothing and is dropped here.
 */
const STATS: readonly { readonly value: string; readonly label: string; readonly unit?: string | undefined }[] = [
  { value: "99.982", label: "Conviction precision", unit: "%" },
  { value: "3", label: "Enforcement rings" },
  { value: "0.018", label: "False-positive rate", unit: "%" },
  { value: "34", label: "Median adjudication", unit: "ms" },
];

export default function Hero(): JSX.Element {
  return (
    <section id="top" className="relative flex min-h-svh flex-col overflow-hidden">
      <HeroCanvas className="pointer-events-none absolute inset-0 h-full w-full opacity-90 [mask-image:linear-gradient(to_bottom,black_60%,transparent_98%)]" />
      <div className="pointer-events-none absolute inset-x-0 top-16 h-px bg-gradient-to-r from-transparent via-line-2 to-transparent" />

      <Reveal className="relative mx-auto flex w-full max-w-[1440px] flex-1 flex-col justify-center px-6 pt-32 pb-16 md:px-10">
        <Reveal className="mb-8 flex flex-wrap items-center gap-x-5 gap-y-2 font-mono text-[10px] uppercase tracking-[0.32em] text-mist md:text-[11px]">
          <span className="flex items-center gap-2 text-volt">
            <Ic name="zap" strokeWidth={2.5} className="h-3.5 w-3.5" /> Ring 0 verified
          </span>
          <span className="hidden h-3 w-px bg-line-2 sm:block" />
          <span>User-Mode</span>
          <span className="text-line-2">/</span>
          <span>Kernel Driver</span>
          <span className="text-line-2">/</span>
          <span>External Arbiter</span>
        </Reveal>

        <div className="relative select-none">
          <Reveal as="h1" variant="blur" className="animate-flicker font-display text-[clamp(5.5rem,20vw,19rem)] font-bold leading-[0.82] tracking-[-0.03em] text-white">
            ZEUS
          </Reveal>
          <span aria-hidden="true">
            <Reveal as="span" delay={90} className="text-hollow pointer-events-none absolute left-[0.35em] top-[0.16em] font-display text-[clamp(5.5rem,20vw,19rem)] font-bold leading-[0.82] tracking-[-0.03em]">
              ZEUS
            </Reveal>
            <Reveal as="span" delay={180} className="text-hollow-volt pointer-events-none absolute left-[0.7em] top-[0.32em] font-display text-[clamp(5.5rem,20vw,19rem)] font-bold leading-[0.82] tracking-[-0.03em] opacity-60">
              ZEUS
            </Reveal>
          </span>
        </div>

        <div className="mt-12 grid gap-10 lg:grid-cols-[1.35fr_1fr] lg:items-end">
          <Reveal delay={120}>
            <p className="max-w-xl text-lg leading-relaxed text-mist md:text-xl">
              A three-ring anti-cheat architecture — a user-mode sentinel, a signed <span className="text-white">kernel driver</span>, and an external server arbiter — built so every conviction is <span className="text-volt">evidence</span>, never collateral damage.
            </p>
            <div className="mt-9 flex flex-wrap items-center gap-4">
              <a
                href="#architecture"
                className="group flex items-center gap-3 bg-volt px-7 py-4 font-mono text-xs font-semibold uppercase tracking-[0.24em] text-abyss transition-all duration-300 hover:shadow-[0_0_44px_rgba(87,224,255,0.45)] clip-notch"
              >
                Inspect the architecture
                <Ic name="cpu" className="h-4 w-4 transition-transform duration-300 group-hover:rotate-90" />
              </a>
              <a
                href="#adjudication"
                className="group flex items-center gap-3 border border-line-2 px-7 py-4 font-mono text-xs uppercase tracking-[0.24em] text-white transition-all duration-300 hover:border-volt/60 hover:text-volt clip-notch"
              >
                <Ic name="shield-check" className="h-4 w-4" />Block ≠ Ban
              </a>
            </div>
          </Reveal>

          <Reveal delay={200} className="grid grid-cols-2 gap-px border border-line bg-line">
            {STATS.map((stat) => (
              <div key={stat.label} className="group bg-ink/80 p-5 backdrop-blur transition-colors duration-300 hover:bg-panel">
                <div className="font-display text-2xl font-semibold text-white md:text-3xl">
                  <span className="tabular-nums">
                    {stat.value}
                    {stat.unit !== undefined ? <span className="text-volt">{stat.unit}</span> : null}
                  </span>
                </div>
                <div className="mt-1.5 font-mono text-[10px] uppercase tracking-[0.2em] text-mist">{stat.label}</div>
              </div>
            ))}
          </Reveal>
        </div>
      </Reveal>

      <Reveal className="relative border-t border-line">
        <div className="mx-auto flex max-w-[1440px] items-center justify-between px-6 py-4 font-mono text-[10px] uppercase tracking-[0.24em] text-mist md:px-10">
          <span className="flex items-center gap-2">
            <Ic name="crosshair" className="h-3.5 w-3.5 text-volt" /> 51.5072° N — ARBITER UPLINK SECURE
          </span>
          <span className="hidden items-center gap-2 md:flex">
            <Ic name="server" className="h-3.5 w-3.5 text-mint" /> OLYMPUS CLUSTER · 12 REGIONS LIVE
          </span>
          <span className="flex items-center gap-2">
            SCROLL <Ic name="chevron-down" className="h-3.5 w-3.5 animate-bounce text-volt" />
          </span>
        </div>
      </Reveal>
    </section>
  );
}
