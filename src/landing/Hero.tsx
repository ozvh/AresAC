import type { JSX } from "react";
import { PUBLIC_SITE } from "./public-mode";
import { Reveal } from "./Reveal";
import { Ic } from "./icons";
const FEATURES = ["Authenticated telemetry", "Server-side decisions", "Auditable evidence"];
export default function Hero(): JSX.Element {
  return <section id="top" className="relative overflow-hidden border-b border-line">
    <div className="mx-auto grid max-w-[1440px] items-center gap-12 px-6 pb-20 pt-36 md:px-10 lg:min-h-[850px] lg:grid-cols-[1.25fr_1fr]">
      <Reveal className="relative z-10">
        <p className="mb-8 font-mono text-[11px] uppercase tracking-[0.28em] text-volt">Integrity is the advantage</p>
        <h1 className="font-display text-[clamp(5rem,12vw,10rem)] font-bold leading-[0.86] tracking-[-0.06em] text-white">ARES</h1>
        <p className="mt-5 font-mono text-lg uppercase tracking-[0.38em] text-volt md:text-2xl">Anti Cheat</p>
        <h2 className="mt-10 max-w-xl font-display text-3xl font-medium leading-tight text-white md:text-4xl">Hold the line.<br /><span className="text-mist">Let the evidence decide.</span></h2>
        <p className="mt-6 max-w-lg text-base leading-relaxed text-mist md:text-lg">An anti-cheat architecture built around authenticated telemetry, server-side adjudication, and a traceable chain of evidence.</p>
        <div className="mt-9 flex flex-wrap gap-4">
          {PUBLIC_SITE
            ? <span className="border border-volt/40 bg-volt/10 px-6 py-4 font-mono text-xs uppercase tracking-[0.16em] text-volt">Private development · not yet available</span>
            : <a href="/console" className="flex items-center gap-3 bg-volt px-6 py-4 font-mono text-xs font-semibold uppercase tracking-[0.16em] text-abyss transition-colors hover:bg-bolt">Open live console <Ic name="arrow-up-right" className="size-4" /></a>}
          <a href="#architecture" className="border border-line-2 px-6 py-4 font-mono text-xs uppercase tracking-[0.16em] text-white transition-colors hover:border-volt">Explore the architecture</a>
        </div>
        <p className="mt-5 font-mono text-[10px] uppercase tracking-[0.12em] text-mist">{PUBLIC_SITE ? "Concept preview · illustrative demonstrations · no public accounts or game service" : "Development preview · Unity telemetry demo available"}</p>
      </Reveal>
      <Reveal delay={100} className="relative mx-auto w-full max-w-[480px]">
        <img src="/images/ares-helmet.svg" alt="Ares shield and helmet emblem" width="480" height="560" className="relative mx-auto w-[75%] lg:w-full" />
        <p className="mt-5 text-center font-mono text-[10px] uppercase tracking-[0.3em] text-mist">Capability before conviction</p>
      </Reveal>
    </div>
    <div className="mx-auto grid max-w-[1440px] border-t border-line px-6 md:grid-cols-3 md:px-10">
      {FEATURES.map((feature, i) => <div key={feature} className="flex items-center gap-5 py-6 font-mono text-xs uppercase tracking-[0.15em]"><span className="text-volt">0{i + 1}</span><span className="text-mist">{feature}</span></div>)}
    </div>
  </section>;
}
