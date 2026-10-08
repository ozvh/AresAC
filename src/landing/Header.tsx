/**
 * The fixed masthead.
 *
 * Five section links, a wordmark that pulses once every 2.6s, a driver-status lamp and the
 * deploy call to action. The whole bar is transparent and stays transparent as the page
 * scrolls — it reads against the drifting backdrop rather than over a filled strip, which is
 * why there is no scroll listener here to add a background at an offset.
 *
 * The status readout carries a live wall clock, as it did in the original page. It is
 * formatted by hand rather than with `toLocaleTimeString`, because the reference shows
 * `HH:MM:SS.cc` — a fixed shape that a locale would be free to reorder, and centiseconds
 * that no locale offers. The interval is 60ms: fast enough that the last two digits appear
 * to move, slow enough to be one cheap state update per frame at most.
 *
 * The deploy button points at this repository's build-request surface. The original used a
 * `#deploy` anchor that scrolled to its own footer; a link that reaches a working form is the
 * same intent with something at the end of it.
 */
import { useEffect, useState } from "react";
import type { JSX } from "react";
import { Ic } from "./icons";

/** The five numbered sections, in document order. */
const NAV: readonly { readonly n: string; readonly label: string; readonly href: string }[] = [
  { n: "01", label: "Architecture", href: "#architecture" },
  { n: "02", label: "Detection", href: "#detection" },
  { n: "03", label: "Adjudication", href: "#adjudication" },
  { n: "04", label: "False Positives", href: "#false-positives" },
  { n: "05", label: "Scaling", href: "#scaling" },
];

/** One shape for all five: an underline that grows from nothing on hover. */
const NAV_LINK =
  "group relative font-mono text-[11px] uppercase tracking-[0.22em] text-mist transition-colors hover:text-white";

/** Zero-padded, two digits. */
function pad(value: number): string {
  return String(value).padStart(2, "0");
}

/** `HH:MM:SS.cc` in local time. Centiseconds are the last two digits of the millisecond. */
function clock(date: Date): string {
  return `${pad(date.getHours())}:${pad(date.getMinutes())}:${pad(date.getSeconds())}.${pad(Math.floor(date.getMilliseconds() / 10))}`;
}

/**
 * Wall clock at ~16 updates a second.
 *
 * The initial value is read synchronously so the first paint shows a real time rather than a
 * placeholder that would visibly repaint: nothing here is server-rendered, so there is no
 * hydration mismatch to avoid and no reason to defer.
 */
function useWallClock(): string {
  const [now, setNow] = useState(() => new Date());

  useEffect(() => {
    const tick = window.setInterval(() => {
      setNow(new Date());
    }, 60);
    return () => {
      window.clearInterval(tick);
    };
  }, []);

  return clock(now);
}

export default function Header(): JSX.Element {
  const now = useWallClock();

  return (
    <header className="fixed inset-x-0 top-0 z-50 transition-all duration-500 bg-transparent">
      <div className="mx-auto flex h-16 max-w-[1440px] items-center justify-between px-6 md:px-10">
        <a href="#top" className="group flex items-center gap-3">
          <span className="relative grid size-9 place-items-center overflow-hidden border border-line-2 bg-panel clip-notch">
            <Ic name="shield-half" strokeWidth={2.4} className="size-4.5 text-volt transition-transform duration-300 group-hover:scale-125" />
            <span className="absolute inset-0 animate-pulse-ring rounded-full border border-volt/40" />
          </span>
          <span className="flex flex-col leading-none">
            <span className="font-display text-lg font-bold tracking-[0.22em] text-white">ARES</span>
            <span className="font-mono text-[9px] uppercase tracking-[0.3em] text-mist">Anti Cheat · v1.0</span>
          </span>
        </a>

        <nav className="hidden items-center gap-8 lg:flex">
          {NAV.map((item) => (
            <a key={item.href} href={item.href} className={NAV_LINK}>
              <span className="mr-1.5 text-volt/60">{item.n}</span>
              {item.label}
              <span className="absolute -bottom-2 left-0 h-px w-0 bg-volt transition-all duration-300 group-hover:w-full" />
            </a>
          ))}
        </nav>

        <div className="flex items-center gap-5">
          <div className="hidden items-center gap-2.5 font-mono text-[10px] tracking-[0.18em] text-mist md:flex">
            <span className="relative flex size-1.5">
              <span className="absolute inline-flex size-full animate-ping rounded-full bg-mint opacity-60" />
              <span className="relative inline-flex size-1.5 rounded-full bg-mint" />
            </span>
            DEVELOPMENT BUILD · <span className="text-volt tabular-nums">{now}</span>
          </div>
          <a
            href="/request"
            className="group flex items-center gap-2 border border-volt/40 bg-volt/10 px-4 py-2 font-mono text-[11px] uppercase tracking-[0.22em] text-volt transition-all duration-300 hover:bg-volt hover:text-abyss hover:shadow-[0_0_30px_rgba(239,121,94,0.4)] clip-notch"
          >
            Deploy
            <Ic name="arrow-up-right" className="size-3.5 transition-transform duration-300 group-hover:translate-x-0.5 group-hover:-translate-y-0.5" />
          </a>
        </div>
      </div>
    </header>
  );
}
