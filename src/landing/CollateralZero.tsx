/**
 * Section 04 — collateral damage zero.
 *
 * The counterweight to the rest of the page. Sections 01–03 argue that ARES can see
 * everything; this one argues that seeing everything is the easy part, and that the failure
 * mode of an anti-cheat is not a missed cheat but a wrongly executed player. Each case card
 * therefore sets a struck-through NAIVE response against the ARES one, side by side, so the
 * comparison is the visual unit rather than a claim in prose.
 *
 * Three blocks, in decreasing order of concrete: the cases, the doctrine behind them, and the
 * escalation ladder that shows the doctrine as a sequence of actions rather than a promise.
 * The ladder's last step is CONVICT, and the gradient bar under it runs mint → volt → blood
 * to say that most of the ladder never reaches the red end.
 *
 * Like the gates above, the cases and the ladder steps are tables rather than repeated
 * markup, and every colour variant is a complete literal class string so Tailwind's static
 * scanner can see it.
 */
import type { JSX } from "react";
import { Ic } from "./icons";
import type { IconName } from "./icons";
import { Reveal } from "./Reveal";

/** One conflict between ARES and ordinary software a player is already running. */
interface Case {
  readonly icon: IconName;
  readonly kicker: string;
  readonly tags: readonly string[];
  readonly body: string;
  /** What a detector without trust chains would do. Always struck through. */
  readonly naive: string;
  readonly ares: string;
}

const CASES: readonly Case[] = [
  {
    icon: "monitor-play",
    kicker: "OVERLAYS & CAPTURE",
    tags: ["Discord", "OBS Studio", "GeForce Experience"],
    body:
      "Frame hooks and overlay injection are byte-identical to a wallhack's draw routine. Any strict user-mode detector screams at them.",
    naive: "code injection detected → flag account",
    ares: "Signed + allowlisted: draw hooks permitted, memory-read primitives stay watched.",
  },
  {
    icon: "shield-alert",
    kicker: "SECURITY SOFTWARE",
    tags: ["Windows Defender", "Third-party AV"],
    body:
      "Two guards wrestling — your driver's monitoring of memory reads looks rootkit-like to AV engines, and naive heuristics mirror-detect the AV's own drivers right back.",
    naive: "driver conflict → instability loops, BSOD risk",
    ares: "Chain-trust attestation: security vendor certificates bypass heuristic blocks entirely.",
  },
  {
    icon: "mouse",
    kicker: "PERIPHERAL SUITES",
    tags: ["Logitech G Hub", "Razer Synapse"],
    body:
      "Low-level input drivers that synthesize keystrokes and clicks are indistinguishable from macro engines to a detector that only watches APIs.",
    naive: "virtual input → aimbot-macro conviction",
    ares: "Input-provenance scoring: vendor chain trusted, timing entropy analyzed — never auto-flagged.",
  },
];

/** One of the three commitments that make the cases above possible. */
interface Doctrine {
  readonly number: string;
  readonly title: string;
  readonly strap: string;
  readonly body: string;
}

const DOCTRINE: readonly Doctrine[] = [
  {
    number: "01",
    title: "Structural Verification",
    strap: "Trust chains, not vibes.",
    body:
      "The driver parses each binary's digital certificate and walks its chain. If a DLL or driver is signed by a trusted authority — Microsoft, NVIDIA, Valve — it bypasses heuristic blocks by design, not by exception.",
  },
  {
    number: "02",
    title: "Dynamic Allowlisting",
    strap: "A corpus, not a hunch.",
    body:
      "A server-synced database of known-good SHA-256 hashes for common overlays, capture suites and system components. Hash matches suppress the alert before it becomes a ticket — the corpus grows with every fleet verdict.",
  },
  {
    number: "03",
    title: "Action Gradation",
    strap: "Block the capability, spare the account.",
    body:
      "User-mode infractions never trigger instant bans. The driver vetoes handle creation or strips access rights via ObRegisterCallbacks — the threat is neutralized silently, and nobody pays for a detector's mistake.",
  },
];

/** Where a response lands on the ladder's severity scale. */
type Rung = "mint" | "volt" | "bolt" | "blood";

/**
 * The rung colours, as literal class strings.
 *
 * The dot's glow is `currentColor`, so one class pair per rung is all it takes for the dot and
 * its label to agree — but both strings still have to be written out, because a name built at
 * runtime is a class Tailwind never generates.
 */
const RUNG: Record<Rung, { readonly dot: string; readonly label: string }> = {
  mint: {
    dot: "h-1.5 w-1.5 rounded-full bg-mint shadow-[0_0_10px_currentColor]",
    label: "font-mono text-[11px] tracking-[0.2em] text-mint",
  },
  volt: {
    dot: "h-1.5 w-1.5 rounded-full bg-volt shadow-[0_0_10px_currentColor]",
    label: "font-mono text-[11px] tracking-[0.2em] text-volt",
  },
  bolt: {
    dot: "h-1.5 w-1.5 rounded-full bg-bolt shadow-[0_0_10px_currentColor]",
    label: "font-mono text-[11px] tracking-[0.2em] text-bolt",
  },
  blood: {
    dot: "h-1.5 w-1.5 rounded-full bg-blood shadow-[0_0_10px_currentColor]",
    label: "font-mono text-[11px] tracking-[0.2em] text-blood",
  },
};

const LADDER: readonly { readonly step: string; readonly rung: Rung }[] = [
  { step: "ALLOW", rung: "mint" },
  { step: "SUPPRESS", rung: "mint" },
  { step: "STRIP RIGHTS", rung: "volt" },
  { step: "VETO HANDLE", rung: "volt" },
  { step: "SHADOW QUEUE", rung: "bolt" },
  { step: "CONVICT", rung: "blood" },
];

export default function CollateralZero(): JSX.Element {
  return (
    <section id="false-positives" className="relative mx-auto max-w-[1440px] px-6 py-28 md:px-10 md:py-40">
      <Reveal className="mb-14 md:mb-20">
        <div className="flex items-center gap-4">
          <span className="font-mono text-[11px] tracking-[0.35em] text-volt">[04]</span>
          <span className="h-px w-10 bg-volt/50" />
          <span className="font-mono text-[11px] uppercase tracking-[0.35em] text-mist">Collateral-Damage Zero</span>
        </div>
        <h2 className="mt-6 max-w-4xl font-display text-4xl font-semibold leading-[1.04] tracking-tight text-white md:text-6xl">
          The cheat isn't the hard target. <span className="text-hollow">Discord is.</span>
        </h2>
        <p className="mt-6 max-w-xl text-base leading-relaxed text-mist md:text-lg">
          When detection spans Ring 3, Ring 0 and the server, harmless software starts to look exactly like a cheat.
          The bottleneck shifts from catching threats to not executing your own players.
        </p>
      </Reveal>

      <div className="grid gap-6 lg:grid-cols-3">
        {CASES.map((item) => (
          <Reveal
            key={item.kicker}
            className="group relative flex flex-col border border-line bg-ink/70 p-7 transition-all duration-500 hover:border-line-2 hover:bg-panel clip-notch"
          >
            <div className="flex items-center gap-4">
              <span className="grid size-11 place-items-center border border-line bg-panel text-bolt transition-colors duration-300 group-hover:border-bolt/40 clip-notch">
                <Ic name={item.icon} strokeWidth={1.7} className="size-5" />
              </span>
              <span className="font-mono text-[11px] tracking-[0.26em] text-bolt">{item.kicker}</span>
            </div>

            <div className="mt-5 flex flex-wrap gap-2">
              {item.tags.map((tag) => (
                <span
                  key={tag}
                  className="border border-line bg-panel px-2.5 py-1 font-mono text-[10px] tracking-[0.14em] text-white/85"
                >
                  {tag}
                </span>
              ))}
            </div>

            <p className="mt-5 flex-1 text-sm leading-relaxed text-mist">{item.body}</p>

            {/* The comparison is the point of the card, so it is set as a pair: one struck
                through, one kept. */}
            <div className="mt-7 space-y-2.5 border-t border-line pt-5 font-mono text-[11px] leading-relaxed">
              <div className="flex gap-2.5 text-blood/90">
                <span className="shrink-0 tracking-[0.14em] text-blood/60">NAIVE</span>
                <span className="line-through decoration-blood/40">{item.naive}</span>
              </div>
              <div className="flex gap-2.5 text-mint/95">
                <span className="shrink-0 tracking-[0.14em] text-mint/60">{"ARES\u00a0\u00a0"}</span>
                <span>{item.ares}</span>
              </div>
            </div>
          </Reveal>
        ))}
      </div>

      <div className="mt-24">
        <Reveal className="mb-10 flex items-center gap-4">
          <span className="h-px w-10 bg-bolt/60" />
          <span className="font-mono text-[11px] uppercase tracking-[0.34em] text-bolt">Tuning Doctrine</span>
        </Reveal>

        <div className="grid gap-px border border-line bg-line lg:grid-cols-3">
          {DOCTRINE.map((rule) => (
            <Reveal
              key={rule.number}
              className="group bg-ink/80 p-8 transition-colors duration-500 hover:bg-panel-2 md:p-10"
            >
              <div className="font-display text-5xl font-bold text-white/[0.07] transition-colors duration-500 group-hover:text-volt/15">
                {rule.number}
              </div>
              <h3 className="mt-4 font-display text-2xl font-semibold text-white">{rule.title}</h3>
              <div className="mt-1.5 font-mono text-xs tracking-[0.16em] text-volt">{rule.strap}</div>
              <p className="mt-4 text-sm leading-relaxed text-mist">{rule.body}</p>
            </Reveal>
          ))}
        </div>

        <Reveal className="mt-6 border border-line bg-ink/60 p-6 md:p-8">
          <div className="flex flex-wrap items-center justify-between gap-3">
            <span className="font-mono text-[10px] tracking-[0.3em] text-mist">
              ESCALATION LADDER — RESPONSE IS GRADED, REVERSIBLE, AND NEVER AMBUSHES A PLAYER
            </span>
            <span className="font-mono text-[10px] tracking-[0.2em] text-blood">BLOCK ≠ BAN</span>
          </div>

          <div className="mt-6 flex flex-wrap items-center gap-y-3">
            {LADDER.map((entry, index) => (
              <div key={entry.step} className="flex items-center">
                <div className="flex items-center gap-2.5 border border-line-2 bg-panel px-4 py-2.5 clip-notch">
                  <span className={RUNG[entry.rung].dot} />
                  <span className={RUNG[entry.rung].label}>{entry.step}</span>
                </div>
                {/* No arrow after the last rung: conviction is where the ladder stops. */}
                {index < LADDER.length - 1 ? (
                  <Ic name="arrow-right" className="mx-2 size-3.5 shrink-0 text-mist/40" />
                ) : null}
              </div>
            ))}
          </div>

          <div className="relative mt-5 h-1 w-full overflow-hidden bg-line">
            <div className="absolute inset-y-0 left-0 w-full bg-gradient-to-r from-mint via-volt via-60% to-blood opacity-70" />
          </div>
        </Reveal>
      </div>
    </section>
  );
}
