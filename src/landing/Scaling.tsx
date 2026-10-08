/**
 * Section 05 — scaling the defence.
 *
 * Two columns that answer the same question from different directions. On the left, the
 * price of each ring as a matrix: what it buys, what it costs, and — in the `Price` cells —
 * what an operator gives up by choosing it, stated as a limit rather than a caveat. On the
 * right, the arbiter's log as it is written.
 *
 * THE FEED IS LIVE, AND THAT IS THE POINT OF THE SECTION. A screenshot of four log lines
 * proves nothing; a list that keeps growing while the reader sits in front of it is the
 * only honest way to show a pipeline that never stops. The original page ran one, and it
 * was not a typing animation — lines arrived on their own cadence with their own
 * timestamps. This reproduces that:
 *
 *  - The pool of lines and the ring badges that colour them are fixed data, so the copy is
 *    the original's and stays reviewable. Only the arrival is dynamic.
 *  - Timestamps are generated rather than replayed. They have to be: each capture of the
 *    original showed different times within the same session, so a fixed table of
 *    timestamps would be a transcription of one moment pretending to be a machine.
 *  - The list is capped. A page left open overnight must not turn into an unbounded array
 *    inside a `space-y-2` flex column, so old rows are dropped from the front once the cap
 *    is reached and the DOM stays the size a reader can actually scroll.
 *
 * The blinking `$` block is the last row rather than a separate element, so that it stays
 * anchored to the end of the log as the log grows, exactly as in the original.
 */
import { useEffect, useRef, useState } from "react";
import type { JSX } from "react";
import { Ic } from "./icons";
import { Reveal } from "./Reveal";

/** The three rows of the matrix. `strength` and `price` are the two captioned cells. */
interface DefenceRow {
  readonly badge: string;
  readonly label: string;
  readonly name: string;
  readonly mechanics: string;
  readonly strength: string;
  readonly price: string;
  readonly row: string;
}

/**
 * Every class here is a complete literal string.
 *
 * Tailwind scans source text, so a class assembled from a variable at runtime is a class
 * that never gets generated. Per-row variation therefore lives in data with the classes
 * spelled out, not in string building.
 */
const DEFENCE_ROWS: readonly DefenceRow[] = [
  {
    badge: "border px-2 py-1 font-mono text-[10px] tracking-[0.24em] text-volt border-volt/40 bg-volt/10",
    label: "RING 3",
    name: "User-Mode",
    mechanics: "Standard Windows APIs, memory hooks, DLL-injection blocking.",
    strength: "Ships fast and fails safe — a fault kills a process, never the machine.",
    price: "Blind spot: kernel-level cheats walk straight past it.",
    row: "group grid grid-cols-1 gap-5 px-6 py-7 transition-colors duration-300 hover:bg-panel md:grid-cols-12 md:gap-px md:py-8 border-b border-line bg-ink/70",
  },
  {
    badge: "border px-2 py-1 font-mono text-[10px] tracking-[0.24em] text-viol border-viol/40 bg-viol/10",
    label: "RING 0",
    name: "Kernel-Mode",
    mechanics: "WDK driver watching process creation, image loads and memory system-wide.",
    strength: "The only depth where advanced cheats cannot hide.",
    price: "BSOD risk — every line demands driver-grade discipline.",
    row: "group grid grid-cols-1 gap-5 px-6 py-7 transition-colors duration-300 hover:bg-panel md:grid-cols-12 md:gap-px md:py-8 border-b border-line bg-ink/70",
  },
  {
    badge: "border px-2 py-1 font-mono text-[10px] tracking-[0.24em] text-mint border-mint/40 bg-mint/10",
    label: "EXTERNAL",
    name: "Server-Side",
    mechanics: "Game logic, movement checks and hit registration computed off-client.",
    strength: "Immune to client-side manipulation — the client can lie, math cannot.",
    price: "Costs continuous, always-on hosting infrastructure.",
    row: "group grid grid-cols-1 gap-5 px-6 py-7 transition-colors duration-300 hover:bg-panel md:grid-cols-12 md:gap-px md:py-8 bg-ink/70",
  },
];

/** The four reporting principals, which is also the set of colours the log uses. */
type Ring = "SRV" | "UMON" | "KMOD" | "JUDGE";

interface FeedLine {
  readonly ring: Ring;
  readonly text: string;
}

interface FeedRow extends FeedLine {
  readonly at: string;
}

/** One badge class per principal. Literal strings, for the same reason as above. */
const RING_BADGE: Record<Ring, string> = {
  SRV: "shrink-0 border px-1.5 py-px text-[9px] font-semibold tracking-[0.14em] text-mint border-mint/40 bg-mint/10",
  UMON: "shrink-0 border px-1.5 py-px text-[9px] font-semibold tracking-[0.14em] text-viol border-viol/40 bg-viol/10",
  KMOD: "shrink-0 border px-1.5 py-px text-[9px] font-semibold tracking-[0.14em] text-volt border-volt/40 bg-volt/10",
  JUDGE: "shrink-0 border px-1.5 py-px text-[9px] font-semibold tracking-[0.14em] text-bolt border-bolt/40 bg-bolt/10",
};

/** The original's own lines, in its own order. The feed cycles through them. */
const FEED: readonly FeedLine[] = [
  { ring: "SRV", text: "hit-reg audit · 312 samples · dispersion within model" },
  { ring: "UMON", text: "overlay hook observed · discord_overlay.dll → allowlist match" },
  { ring: "UMON", text: "anti-debug: PEB.BeingDebugged=0 · timing delta nominal" },
  { ring: "KMOD", text: "image load vetted · nvshader64.dll → chain OK (Microsoft)" },
  { ring: "UMON", text: "anti-debug: PEB.BeingDebugged=0 · timing delta nominal" },
  { ring: "SRV", text: "movement replay OK · player 88f2c1 · deviation 0.31σ" },
  { ring: "SRV", text: "movement replay OK · player 88f2c1 · deviation 0.31σ" },
  { ring: "JUDGE", text: "graded response: STRIP rights (pid 9921) · silent" },
  { ring: "KMOD", text: "PsNotify: regsvr spawned → parentage audited · clean" },
  { ring: "SRV", text: "allowlist delta pushed · +84 hashes · TTL 90s" },
  { ring: "KMOD", text: "ObCallback veto: handle request denied · pid 4410 (unsigned)" },
  { ring: "SRV", text: "movement replay OK · player 88f2c1 · deviation 0.31σ" },
  { ring: "SRV", text: "fleet heartbeat · 12/12 regions nominal · lag p99 22ms" },
  { ring: "JUDGE", text: "gate 01 unsigned binary · contained · user unaffected" },
  { ring: "SRV", text: "movement replay OK · player 88f2c1 · deviation 0.31σ" },
  { ring: "SRV", text: "allowlist delta pushed · +84 hashes · TTL 90s" },
  { ring: "SRV", text: "arbiter verdict: BENIGN · confidence 99.72%" },
  { ring: "UMON", text: "injection blocked · LoadLibraryW from unsigned module" },
  { ring: "KMOD", text: "stripped PROCESS_VM_WRITE · pid 11872 → game.exe (Synapse3.exe)" },
  { ring: "UMON", text: "obs64.exe present-hook → signed + allowlisted · pass" },
  { ring: "KMOD", text: "process birth intercepted · ce_scanner.exe → quarantined" },
  { ring: "UMON", text: "signature sweep: 0 hits · corpus rev 29,411" },
];

/**
 * The feed is a WINDOW, not a log, and the size of that window is load-bearing.
 *
 * The panel is `h-full` inside a grid whose row height the left-hand matrix decides, so the
 * feed has a fixed amount of room and no more. A list that outgrows that room does not
 * scroll inside it — it stretches the grid row, and with it the whole section: measured
 * against the deployed page, forty rendered rows made section 05 roughly 800px taller than
 * the original, which is the opposite of reproducing it. So the window is pinned to the
 * sixteen log rows the original kept on screen (its own scroll container reported a client
 * height exactly equal to its scroll height, which is a window that fits, not a scroller
 * with slack), and each arriving line pushes the oldest out of the top.
 *
 * The pool below is longer than the window on purpose. It is the corpus the deployed page was
 * observed emitting — every line in it was read off that page — and the feed slides a
 * sixteen-row window through it, oldest out of the top, so what a visitor sees is drawn from
 * the same set of events the original drew from. The reference markup captured one window of
 * it, not the corpus behind it, so the remaining lines were recovered by diffing the live
 * page's log against that capture.
 */
const WINDOW_ROWS = 16;

/** Cadence of an arriving line. The original was irregular by a few hundred milliseconds. */
const TICK_MS = 1100;

/** The feed's clock starts here; `18:07:31.422` is the first timestamp the original showed. */
const CLOCK_BASE_MS = ((18 * 60 + 7) * 60 + 31) * 1000 + 422;

/** `HH:MM:SS.mmm`, zero-padded, from a millisecond offset. */
function stamp(ms: number): string {
  const total = Math.floor(ms);
  const pad = (value: number, width: number): string => String(value).padStart(width, "0");
  return (
    `${pad(Math.floor(total / 3600000) % 24, 2)}:` +
    `${pad(Math.floor(total / 60000) % 60, 2)}:` +
    `${pad(Math.floor(total / 1000) % 60, 2)}.` +
    `${pad(total % 1000, 3)}`
  );
}

/**
 * The seeded opening state, built once at module scope.
 *
 * Module scope rather than a `useState` initialiser because the feed's clock and its cursor
 * into the pool have to start from exactly the values that produced the visible rows. Two
 * independent initialisers would drift apart on the first append, and StrictMode's double
 * render would run them twice.
 */
const SEEDED: { readonly rows: readonly FeedRow[]; readonly clock: number; readonly cursor: number } = (() => {
  const rows: FeedRow[] = [];
  let clock = CLOCK_BASE_MS;
  for (let i = 0; i < WINDOW_ROWS; i += 1) {
    const line = FEED[i];
    if (line === undefined) break;
    clock += 300 + Math.random() * 600;
    rows.push({ at: stamp(clock), ring: line.ring, text: line.text });
  }
  return { rows, clock, cursor: WINDOW_ROWS - 1 };
})();

/**
 * The log body, which is the only moving part of the section.
 *
 * `scroll-smooth` in the original means the container is meant to be seen travelling, so the
 * scroll to the newest row is a plain assignment rather than an instant jump; the browser
 * animates it, and the reader's eye has somewhere to land.
 */
function LiveFeed(): JSX.Element {
  const [rows, setRows] = useState<readonly FeedRow[]>(SEEDED.rows);
  const clock = useRef(SEEDED.clock);
  const cursor = useRef(SEEDED.cursor);
  const scroller = useRef<HTMLDivElement | null>(null);

  useEffect(() => {
    const id = window.setInterval(() => {
      cursor.current += 1;
      clock.current += 300 + Math.random() * 600;
      // The pool wraps rather than ending: the arbiter is a system that keeps reporting.
      const line = FEED[cursor.current % FEED.length];
      if (line === undefined) return;
      setRows((previous) => {
        const grown = [...previous, { at: stamp(clock.current), ring: line.ring, text: line.text }];
        return grown.length > WINDOW_ROWS ? grown.slice(grown.length - WINDOW_ROWS) : grown;
      });
    }, TICK_MS);
    return () => window.clearInterval(id);
  }, []);

  useEffect(() => {
    const element = scroller.current;
    if (element === null) return;
    element.scrollTop = element.scrollHeight;
  }, [rows.length]);

  return (
    <div
      ref={scroller}
      className="flex-1 space-y-2 overflow-y-auto scroll-smooth p-5 font-mono text-[11px] leading-relaxed"
    >
      {rows.map((row, index) => (
        // Rows are only ever appended or dropped from the front, so the row's own timestamp
        // is a stable identity for it — better than the index, which shifts as rows age out.
        <div key={`${index}-${row.at}`} className="flex items-start gap-3">
          <span className="shrink-0 pt-px tabular-nums text-mist/50">{row.at}</span>
          <span className={RING_BADGE[row.ring]}>{row.ring}</span>
          <span className="min-w-0 break-words text-white/80">{row.text}</span>
        </div>
      ))}
      <div className="flex items-center gap-3 pt-1">
        <span className="text-mist/50">$</span>
        <span className="inline-block h-3.5 w-2 animate-blink bg-volt"></span>
      </div>
    </div>
  );
}

export default function Scaling(): JSX.Element {
  return (
    <section id="scaling" className="relative border-t border-line bg-ink/40">
      <div className="mx-auto max-w-[1440px] px-6 py-28 md:px-10 md:py-40">
        <Reveal className="mb-14 md:mb-20">
          <div className="flex items-center gap-4">
            <span className="font-mono text-[11px] tracking-[0.35em] text-volt">[05]</span>
            <span className="h-px w-10 bg-volt/50"></span>
            <span className="font-mono text-[11px] uppercase tracking-[0.35em] text-mist">Scaling The Defense</span>
          </div>
          <h2 className="mt-6 max-w-4xl font-display text-4xl font-semibold leading-[1.04] tracking-tight text-white md:text-6xl">
            Choose your ring. <span className="text-hollow">Know its price.</span>
          </h2>
          <p className="mt-6 max-w-xl text-base leading-relaxed text-mist md:text-lg">
            No single layer is universal. ARES assumes each ring trades capability against risk — and engineers the
            combination so the weaknesses cancel out.
          </p>
        </Reveal>

        <div className="grid gap-10 lg:grid-cols-12">
          <Reveal className="lg:col-span-7">
            <div className="overflow-hidden border border-line">
              <div className="hidden grid-cols-12 gap-px border-b border-line bg-ink px-6 py-3.5 font-mono text-[10px] uppercase tracking-[0.26em] text-mist md:grid">
                <span className="col-span-3">Defense Level</span>
                <span className="col-span-4">Mechanics</span>
                <span className="col-span-3">Strength</span>
                <span className="col-span-2">Price</span>
              </div>

              {DEFENCE_ROWS.map((entry) => (
                <div key={entry.name} className={entry.row}>
                  <div className="col-span-3 flex flex-row items-center gap-4 md:flex-col md:items-start md:gap-3">
                    <span className={entry.badge}>{entry.label}</span>
                    <span className="font-display text-xl font-semibold text-white md:text-2xl">{entry.name}</span>
                  </div>
                  <p className="col-span-4 text-sm leading-relaxed text-mist md:pr-6">{entry.mechanics}</p>
                  <div className="col-span-3 flex gap-3 md:pr-6">
                    <Ic name="trending-up" className="mt-0.5 size-4 shrink-0 text-mint" />
                    <p className="text-sm leading-relaxed text-white/80">{entry.strength}</p>
                  </div>
                  <div className="col-span-2 flex gap-3">
                    <Ic name="triangle-alert" className="mt-0.5 size-4 shrink-0 text-bolt" />
                    <p className="text-sm leading-relaxed text-mist/80">{entry.price}</p>
                  </div>
                </div>
              ))}
            </div>

            <div className="mt-5 flex flex-wrap items-center justify-between gap-3 border border-line bg-ink/50 px-6 py-4 font-mono text-[10px] tracking-[0.18em] text-mist">
              <span className="flex items-center gap-2">
                <Ic name="terminal" className="size-3.5 text-volt" />
                BUILD CHAIN — VISUAL STUDIO 2022 · MSVC v143 · WDK 10.0.22621 · EV ATTESTATION SIGNING
              </span>
              <span className="text-mint">ALL RINGS GREEN</span>
            </div>
          </Reveal>

          <Reveal className="lg:col-span-5">
            <div className="panel flex h-full min-h-[460px] flex-col overflow-hidden">
              <div className="flex items-center justify-between border-b border-line px-5 py-3.5">
                <div className="flex items-center gap-2">
                  <span className="size-2.5 rounded-full bg-blood/70"></span>
                  <span className="size-2.5 rounded-full bg-bolt/70"></span>
                  <span className="size-2.5 rounded-full bg-mint/70"></span>
                </div>
                <span className="font-mono text-[10px] tracking-[0.22em] text-mist">
                  ares@olympus-arbiter — adjudication feed
                </span>
                <span className="hidden font-mono text-[10px] tracking-[0.14em] text-mist/50 sm:block">
                  {"\\\\.\\pipe\\ares_kmod"}
                </span>
              </div>

              <LiveFeed />

              <div className="flex items-center justify-between border-t border-line px-5 py-3 font-mono text-[10px] tracking-[0.18em] text-mist">
                <span>
                  λ <span className="text-volt">1,204</span> evt/s · loss <span className="text-mint">0.000%</span>
                </span>
                <span className="hidden sm:block">PIPE SEALED · AES-256-GCM</span>
              </div>
            </div>
          </Reveal>
        </div>
      </div>
    </section>
  );
}
