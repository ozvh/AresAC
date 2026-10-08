/**
 * Detection doctrine: four pillars, zero blind spots.
 *
 * The four cards are one component rendered four times, because the original built them from
 * a single template — the classes are identical across all four and only the glyph, the
 * index, the copy and the tag row differ. Keeping the class strings in this file, once,
 * means a change to the card treatment cannot be applied to three of them.
 *
 * The watermark behind the heading (`RING`, at 2% white) is decorative and hidden below the
 * `xl` breakpoint, exactly as the original had it.
 */
import type { JSX } from "react";
import { Ic, type IconName } from "./icons";
import { Reveal } from "./Reveal";

/** One detection pillar. */
interface Pillar {
  readonly glyph: IconName;
  /** The `/01`-style index in the card's top-right corner. */
  readonly index: string;
  readonly title: string;
  readonly body: string;
  /** Short capability chips under the copy. */
  readonly tags: readonly string[];
}

/** Shared card chrome: the sweep that passes behind the card on hover, and the top rule. */
const CARD = "group relative overflow-hidden bg-ink/80 p-8 transition-colors duration-500 hover:bg-panel-2 md:p-10";
const CARD_SWEEP =
  "pointer-events-none absolute inset-x-0 top-0 h-24 -translate-y-full bg-gradient-to-b from-transparent via-volt/[0.07] to-transparent transition-transform duration-700 group-hover:translate-y-[400%]";
const CARD_RULE = "absolute inset-x-0 top-0 h-[2px] w-0 bg-volt transition-all duration-500 group-hover:w-full";
const CARD_TILE =
  "grid h-14 w-14 place-items-center border border-line bg-panel text-volt transition-all duration-500 group-hover:border-volt/50 group-hover:shadow-[0_0_30px_rgba(87,224,255,0.25)] clip-notch";
const CARD_INDEX = "font-mono text-[11px] tracking-[0.3em] text-mist/50 transition-colors group-hover:text-volt";
const CARD_TAG =
  "border border-line px-2.5 py-1 font-mono text-[10px] tracking-[0.16em] text-mist/80 transition-colors duration-300 group-hover:border-volt/30 group-hover:text-volt/90";

const PILLARS: readonly Pillar[] = [
  {
    glyph: "hash",
    index: "/01",
    title: "Memory Integrity",
    body: "Continuously re-hash the game's executable sections and compare against signed gold images. One flipped instruction — one injected byte — breaks the chain and raises the event.",
    tags: ["SHA-256", ".text audit", "gold-image diff"],
  },
  {
    glyph: "hand",
    index: "/02",
    title: "Handle Stripping",
    body: "Kernel callbacks intercept every handle opened toward the game. PROCESS_VM_READ / WRITE rights are stripped from anything that fails attestation — the read simply never happens.",
    tags: ["ObRegisterCallbacks", "PROCESS_VM_READ", "access veto"],
  },
  {
    glyph: "scan-search",
    index: "/03",
    title: "Heuristic Pattern Scan",
    body: "Loaded modules and system memory are swept for the signatures, strings and allocation patterns that cheat tools leave behind — matched against a fleet-synced corpus, updated by the hour.",
    tags: ["signature DB", "YARA-class", "delta sync"],
  },
  {
    glyph: "bug-off",
    index: "/04",
    title: "Anti-Debug Mesh",
    body: "Layered checks — from IsDebuggerPresent to raw PEB and NtQueryInformationProcess reads — detect attachment attempts and make live reverse-engineering a losing game.",
    tags: ["PEB flags", "NtQuery", "timing traps"],
  },
];

export default function Detection(): JSX.Element {
  return (
    <section id="detection" className="relative mx-auto max-w-[1440px] px-6 py-28 md:px-10 md:py-40">
      <div className="pointer-events-none absolute right-0 top-0 hidden select-none font-display text-[18rem] font-bold leading-none text-white/[0.02] xl:block">
        RING
      </div>

      <Reveal className="mb-14 md:mb-20">
        <div className="flex items-center gap-4">
          <span className="font-mono text-[11px] tracking-[0.35em] text-volt">[02]</span>
          <span className="h-px w-10 bg-volt/50" />
          <span className="font-mono text-[11px] uppercase tracking-[0.35em] text-mist">Detection Doctrine</span>
        </div>
        <h2 className="mt-6 max-w-4xl font-display text-4xl font-semibold leading-[1.04] tracking-tight text-white md:text-6xl">
          Four pillars. <span className="text-hollow">Zero blind spots.</span>
        </h2>
        <p className="mt-6 max-w-xl text-base leading-relaxed text-mist md:text-lg">
          Different cheats live at different depths — so detection stack-ranks structural proof over behavioral
          guesses. Every pillar feeds the same evidence pipeline.
        </p>
      </Reveal>

      <div className="grid gap-px border border-line bg-line md:grid-cols-2">
        {PILLARS.map((pillar) => (
          <Reveal key={pillar.index} className={CARD}>
            <span className={CARD_SWEEP} />
            <span className={CARD_RULE} />
            <div className="relative">
              <div className="flex items-start justify-between">
                <span className={CARD_TILE}>
                  <Ic name={pillar.glyph} strokeWidth={1.6} className="h-6 w-6" />
                </span>
                <span className={CARD_INDEX}>{pillar.index}</span>
              </div>
              <h3 className="mt-7 font-display text-2xl font-semibold text-white md:text-3xl">{pillar.title}</h3>
              <p className="mt-4 max-w-md leading-relaxed text-mist">{pillar.body}</p>
              <div className="mt-7 flex flex-wrap gap-2">
                {pillar.tags.map((tag) => (
                  <span key={tag} className={CARD_TAG}>
                    {tag}
                  </span>
                ))}
              </div>
            </div>
          </Reveal>
        ))}
      </div>
    </section>
  );
}
