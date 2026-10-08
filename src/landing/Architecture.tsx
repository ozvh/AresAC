/**
 * System architecture: three rings, one verdict.
 *
 * One interactive piece on an otherwise static page. The left column is a stack of three
 * ring buttons; the right is the detail panel for whichever ring is selected, and the page
 * loads with the kernel ring already chosen — that is the state the original served, so it
 * is the initial state here.
 *
 * The reason the ring data below carries so many class strings is that the accent changes
 * per ring: volt for the sentinel, violet for the driver, mint for the arbiter. Tailwind
 * scans source for complete class names, so `border-${accent}/40` would compile to nothing.
 * Every variant is therefore spelled out in full. It is verbose and it is the only way this
 * stays working after a rebuild.
 *
 * The panel is keyed by the selected ring so switching re-mounts it, which replays the
 * blur-to-sharp entrance the original ran on each change rather than silently swapping text.
 */
import { useState } from "react";
import type { JSX } from "react";
import { Ic, type IconName } from "./icons";
import { Reveal } from "./Reveal";

/** One numbered capability row inside a ring panel. */
interface RingItem {
  readonly title: string;
  readonly mechanism: string;
}

/**
 * A ring and every class that depends on its accent.
 *
 * `selected*` fields are only applied to the button for that ring; the shared constants below
 * cover the unselected case, which is identical for all three.
 */
interface Ring {
  /** `RING 3` / `RING 0` / `EXTERNAL`, as the small label above the ring's name. */
  readonly tag: string;
  readonly title: string;
  /** Glyph on the selector button. */
  readonly glyph: IconName;
  /** Selected selector button: panel fill, accent border, inset wash. */
  readonly selectedButton: string;
  /** Selected glyph tile on the selector button. */
  readonly selectedIcon: string;
  /** Selected ring label colour on the selector button. */
  readonly selectedLabel: string;
  /** Selected chevron colour; the original also nudged it one step right. */
  readonly selectedChevron: string;
  /** 2px accent bar across the top of the detail panel. */
  readonly bar: string;
  /** The panel's own badge, e.g. `RING 0`. */
  readonly badge: string;
  /** One-line file identity under the panel heading, e.g. `ares.sys · kernel driver`. */
  readonly file: string;
  /** The accent-coloured line under the panel heading. */
  readonly tagline: string;
  readonly taglineClass: string;
  /** Large watermark glyph in the panel's top-right corner. */
  readonly watermark: string;
  /** Colour of the numbered rows' indices. */
  readonly index: string;
  readonly body: string;
  readonly items: readonly RingItem[];
  /** Accent for the two cards at the foot of the panel. */
  readonly commsIcon: string;
  readonly commsValue: string;
  readonly commsChannel: string;
  readonly commsBody: string;
  readonly blastRadius: string;
}

/** Padding, shape and hover shared by all three selector buttons. */
const BUTTON_BASE = "group relative -ml-6 flex items-center gap-5 border p-5 text-left transition-all duration-300";
/** The unselected button: hairline border on a translucent ink fill. */
const BUTTON_IDLE = "clip-notch border-line bg-ink/50 hover:border-line-2 hover:bg-panel/60";
const ICON_BASE = "grid h-12 w-12 shrink-0 place-items-center transition-all duration-300 clip-notch";
const ICON_IDLE = "border border-line bg-panel text-mist group-hover:text-white";
const LABEL_IDLE = "font-mono text-[10px] tracking-[0.3em] text-mist";
const CHEVRON_BASE = "h-4 w-4 transition-all duration-300";
const CHEVRON_IDLE = "text-mist/40";
const ROW_BASE = "group flex items-start justify-between gap-4 bg-ink/70 p-4 transition-colors duration-300 hover:bg-panel-2";
const FOOT_CARD = "border border-line bg-ink/50 p-4";
const FOOT_LABEL = "flex items-center gap-2 font-mono text-[10px] tracking-[0.24em] text-mist";

const RINGS: readonly Ring[] = [
  {
    tag: "RING 3",
    title: "ARES Sentinel",
    glyph: "scan-eye",
    selectedButton: "clip-notch bg-panel border-volt/50 shadow-[inset_0_0_40px_rgba(239,121,94,0.04)]",
    selectedIcon: "border border-volt/30 bg-volt/10 text-volt",
    selectedLabel: "font-mono text-[10px] tracking-[0.3em] text-volt",
    selectedChevron: "text-volt translate-x-1",
    bar: "absolute inset-x-0 top-0 h-[2px] bg-volt",
    badge: "border px-2.5 py-1 font-mono text-[10px] tracking-[0.3em] border-volt/30 bg-volt/10 text-volt",
    file: "sentinel.exe · user-mode",
    tagline: "First contact. In-proc eyes on the process.",
    taglineClass: "mt-2 font-mono text-xs tracking-[0.12em] text-volt",
    watermark: "h-14 w-14 md:h-20 md:w-20 text-volt opacity-80",
    index: "mt-0.5 font-mono text-[10px] text-volt",
    body: "The sentinel lives beside the game — a hardened user-mode module that owns everything Ring 3 can see: loaded modules, injected threads, overlay hooks and the integrity of the game's own code pages.",
    items: [
      { title: "Signature & pattern engine", mechanism: "yara-class · SIMD scan" },
      { title: "DLL-injection blocking", mechanism: "LoadLibrary detours" },
      { title: "Anti-debug suite", mechanism: "PEB · NtQueryInformationProcess" },
      { title: "Image integrity verification", mechanism: "SHA-256 · .text segment" },
      { title: "Overlay & capture sanity rules", mechanism: "present-hook audit" },
    ],
    commsIcon: "h-3.5 w-3.5 text-volt",
    commsValue: "mt-2 font-mono text-xs font-semibold tracking-[0.14em] text-volt",
    commsChannel: "NAMED PIPE · ALPC",
    commsBody: "Sentinel → service heartbeat every 250 ms. Sealed, sequence-checked packets — a dead sentinel is itself a signal.",
    blastRadius: "PROCESS-LOCAL — a sentinel fault kills one worker, never the session.",
  },
  {
    tag: "RING 0",
    title: "ARES Kernel",
    glyph: "circuit-board",
    selectedButton: "clip-notch bg-panel border-viol/60 shadow-[inset_0_0_40px_rgba(239,121,94,0.04)]",
    selectedIcon: "border border-viol/40 bg-viol/10 text-viol",
    selectedLabel: "font-mono text-[10px] tracking-[0.3em] text-viol",
    selectedChevron: "text-viol translate-x-1",
    bar: "absolute inset-x-0 top-0 h-[2px] bg-viol",
    badge: "border px-2.5 py-1 font-mono text-[10px] tracking-[0.3em] border-viol/40 bg-viol/10 text-viol",
    file: "ares.sys · kernel driver",
    tagline: "The high ground. Nothing hides below it.",
    taglineClass: "mt-2 font-mono text-xs tracking-[0.12em] text-viol",
    watermark: "h-14 w-14 md:h-20 md:w-20 text-viol opacity-80",
    index: "mt-0.5 font-mono text-[10px] text-viol",
    body: "A signed WDK driver that watches the watchmen. Ares.sys intercepts handle creation, image loads and process birth system-wide — vetoing abuse before user-mode code ever executes.",
    items: [
      { title: "Handle-creation veto & access stripping", mechanism: "ObRegisterCallbacks" },
      { title: "Process-birth interdiction", mechanism: "PsSetCreateProcessNotifyRoutineEx" },
      { title: "Unsigned driver & image blocking", mechanism: "PsSetLoadImageNotifyRoutine" },
      { title: "APC / thread-injection watch", mechanism: "KeStackAttachProcess audit" },
      { title: "Cheat-tool I/O interdiction", mechanism: "minifilter · FltRegisterFilter" },
    ],
    commsIcon: "h-3.5 w-3.5 text-viol",
    commsValue: "mt-2 font-mono text-xs font-semibold tracking-[0.14em] text-viol",
    commsChannel: "IOCTL 0x9C40 · SHARED SECTION",
    commsBody: "Up: read-only event queue, driver → service. Down: schema-validated, rate-limited control channel — no arbitrary writes, ever.",
    blastRadius: "SYSTEM-WIDE — written to a zero-BSOD doctrine: third-party driver memory is never dereferenced.",
  },
  {
    tag: "EXTERNAL",
    title: "Ares Arbiter",
    glyph: "globe",
    selectedButton: "clip-notch bg-panel border-mint/50 shadow-[inset_0_0_40px_rgba(239,121,94,0.04)]",
    selectedIcon: "border border-mint/30 bg-mint/10 text-mint",
    selectedLabel: "font-mono text-[10px] tracking-[0.3em] text-mint",
    selectedChevron: "text-mint translate-x-1",
    bar: "absolute inset-x-0 top-0 h-[2px] bg-mint",
    badge: "border px-2.5 py-1 font-mono text-[10px] tracking-[0.3em] border-mint/30 bg-mint/10 text-mint",
    file: "arbiter.ares · server-side",
    tagline: "The court of final appeal — off the client entirely.",
    taglineClass: "mt-2 font-mono text-xs tracking-[0.12em] text-mint",
    watermark: "h-14 w-14 md:h-20 md:w-20 text-mint opacity-80",
    index: "mt-0.5 font-mono text-[10px] text-mint",
    body: "Nothing on the player's machine is trusted as fact. Movement, hit registration and economy are re-derived on hardware the cheater cannot touch, and a statistical model decides what telemetry cannot.",
    items: [
      { title: "Movement & input plausibility", mechanism: "tick-perfect replay" },
      { title: "Authoritative hit registration", mechanism: "server-side raycast" },
      { title: "Statistical conviction model", mechanism: "aim-deviation scorer" },
      { title: "Fleet allowlist & signature sync", mechanism: "delta push · 90s TTL" },
      { title: "Shadow-review queues", mechanism: "human analyst lane" },
    ],
    commsIcon: "h-3.5 w-3.5 text-mint",
    commsValue: "mt-2 font-mono text-xs font-semibold tracking-[0.14em] text-mint",
    commsChannel: "mTLS 1.3 UPLINK",
    commsBody: "Certificate-pinned telemetry, replay-resistant, batched in 5 s windows. The client can lie — the physics cannot.",
    blastRadius: "CLIENT-PROOF — compromise of the endpoint yields telemetry noise, not authority.",
  },
];

/** The kernel ring, and the state the deployed page came up in. */
const DEFAULT_RING = 1;

export default function Architecture(): JSX.Element {
  const [selected, setSelected] = useState(DEFAULT_RING);
  const ring = RINGS[selected] ?? RINGS[DEFAULT_RING];
  if (ring === undefined) throw new Error("ARES landing: the ring table is empty");

  return (
    <section id="architecture" className="relative mx-auto max-w-[1440px] px-6 py-28 md:px-10 md:py-40">
      <Reveal className="mb-14 md:mb-20">
        <div className="flex items-center gap-4">
          <span className="font-mono text-[11px] tracking-[0.35em] text-volt">[01]</span>
          <span className="h-px w-10 bg-volt/50" />
          <span className="font-mono text-[11px] uppercase tracking-[0.35em] text-mist">System Architecture</span>
        </div>
        <h2 className="mt-6 max-w-4xl font-display text-4xl font-semibold leading-[1.04] tracking-tight text-white md:text-6xl">
          Three rings. <span className="text-hollow-volt">One verdict.</span>
        </h2>
        <p className="mt-6 max-w-xl text-base leading-relaxed text-mist md:text-lg">
          Cheats operate at every depth of the operating system — from Notepad-grade memory editors to signed kernel
          drivers. ARES mirrors that depth: each ring watches exactly what the others cannot see.
        </p>
      </Reveal>

      <div className="grid gap-8 lg:grid-cols-[minmax(300px,400px)_1fr]">
        <Reveal className="relative">
          <div className="relative flex flex-col gap-4 pl-6">
            <div className="absolute left-[5px] top-4 bottom-4 w-px bg-gradient-to-b from-line-2 via-volt/40 to-line-2" />
            <span className="packet-dot absolute left-[2.5px] h-1.5 w-1.5 rounded-full bg-volt shadow-[0_0_12px_rgba(239,121,94,0.9)]" />
            <span className="packet-dot absolute left-[2.5px] h-1.5 w-1.5 rounded-full bg-viol shadow-[0_0_12px_rgba(201,167,119,0.9)] [animation-delay:1.55s]" />

            {RINGS.map((entry, index) => {
              const active = index === selected;
              return (
                <button
                  key={entry.tag}
                  type="button"
                  aria-pressed={active}
                  onClick={() => {
                    setSelected(index);
                  }}
                  className={`${BUTTON_BASE} ${active ? entry.selectedButton : BUTTON_IDLE}`}
                >
                  <span className={`${ICON_BASE} ${active ? entry.selectedIcon : ICON_IDLE}`}>
                    <Ic name={entry.glyph} strokeWidth={1.8} className="h-5 w-5" />
                  </span>
                  <span className="flex-1">
                    <span className={active ? entry.selectedLabel : LABEL_IDLE}>{entry.tag}</span>
                    <span className="block font-display text-lg font-semibold text-white">{entry.title}</span>
                  </span>
                  <Ic
                    name="chevron-right"
                    className={`${CHEVRON_BASE} ${active ? entry.selectedChevron : CHEVRON_IDLE}`}
                  />
                </button>
              );
            })}
          </div>

          <div className="mt-6 hidden border border-line bg-ink/40 p-4 font-mono text-[10px] leading-relaxed tracking-[0.14em] text-mist lg:block">
            <span className="text-volt">// SELECTION PROTOCOL</span>
            <br />
            Each ring reports independently; the arbiter convicts only on cross-ring corroboration or behavioral
            certainty.
          </div>
        </Reveal>

        <Reveal className="min-h-[560px]">
          <Reveal key={ring.tag} variant="blur" className="panel relative h-full overflow-hidden clip-notch">
            <span className={ring.bar} />
            <div className="pointer-events-none absolute -right-24 -top-24 h-72 w-72 rounded-full bg-[radial-gradient(circle,rgba(239,121,94,0.09),transparent_65%)]" />

            <div className="relative flex h-full flex-col p-7 md:p-10">
              <div className="flex flex-wrap items-start justify-between gap-6">
                <div>
                  <div className="flex items-center gap-3">
                    <span className={ring.badge}>{ring.tag}</span>
                    <span className="font-mono text-[10px] tracking-[0.2em] text-mist">{ring.file}</span>
                  </div>
                  <h3 className="mt-4 font-display text-3xl font-bold text-white md:text-5xl">{ring.title}</h3>
                  <p className={ring.taglineClass}>{ring.tagline}</p>
                </div>
                <Ic name={ring.glyph} strokeWidth={1} className={ring.watermark} />
              </div>

              <p className="mt-6 max-w-2xl leading-relaxed text-mist">{ring.body}</p>

              <div className="mt-8 grid gap-px border border-line bg-line md:grid-cols-1 lg:grid-cols-2">
                {ring.items.map((item, index) => (
                  <div key={item.title} className={ROW_BASE}>
                    <div className="flex items-start gap-3">
                      <span className={ring.index}>{String(index + 1).padStart(2, "0")}</span>
                      <span className="text-sm text-white/90">{item.title}</span>
                    </div>
                    <span className="whitespace-nowrap font-mono text-[10px] tracking-wide text-mist/70 group-hover:text-mist">
                      {item.mechanism}
                    </span>
                  </div>
                ))}
              </div>

              <div className="mt-auto grid gap-4 pt-8 md:grid-cols-2">
                <div className={FOOT_CARD}>
                  <div className={FOOT_LABEL}>
                    <Ic name="arrow-left-right" className={ring.commsIcon} /> COMMS CHANNEL
                  </div>
                  <div className={ring.commsValue}>{ring.commsChannel}</div>
                  <p className="mt-2 text-xs leading-relaxed text-mist/90">{ring.commsBody}</p>
                </div>
                <div className={FOOT_CARD}>
                  <div className={FOOT_LABEL}>
                    <Ic name="shield-half" className={ring.commsIcon} /> BLAST RADIUS
                  </div>
                  <p className="mt-2 text-xs leading-relaxed text-white/85">{ring.blastRadius}</p>
                </div>
              </div>
            </div>
          </Reveal>
        </Reveal>
      </div>
    </section>
  );
}
