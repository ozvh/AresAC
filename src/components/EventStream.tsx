/**
 * Adjudicated event stream.
 *
 * The buffer holds up to 60,000 events; the DOM holds roughly forty rows. Only the
 * window intersecting the viewport is rendered, positioned absolutely inside a
 * spacer whose height is derived arithmetically from the buffer length — so the
 * browser is never asked to measure 60,000 nodes, and a commit costs the same at
 * three events per second as at three thousand.
 *
 * Autoscroll obeys the operator: scrolling up detaches the view and freezes it in
 * place, because a console that yanks text out from under someone reading it is
 * worse than one that falls behind.
 */
import { useLayoutEffect, useRef, useState, type JSX } from "react";
import { CODE_LABEL, GATE_LABEL, type PublicEvent } from "@shared/protocol";
import { useConsole, useEventRing } from "@/lib/store";
import { DISPOSITION_TEXT, ROLE_RING_LABEL } from "@/lib/theme";
import { bar, clock, compact, padZero } from "@/lib/format";

/** Must match `.row-h` in index.css: the virtualiser and the stylesheet share it. */
const ROW_H = 18;
const OVERSCAN = 8;

const GRID =
  "grid grid-cols-[54px_84px_58px_26px_94px_44px_104px_32px_58px_minmax(0,1fr)] items-center gap-x-2 px-2";

function EventRow({ event, top }: { event: PublicEvent; top: number }): JSX.Element {
  const kernel = event.role === "KMOD";
  return (
    <div className={`${GRID} row-h absolute inset-x-0 whitespace-nowrap`} style={{ top }}>
      <span className="num text-dimmer">{padZero(event.q % 100000, 5)}</span>
      <span className="num text-dim">{clock(event.ts)}</span>
      <span className="text-dim">{event.ag}</span>
      <span className={kernel ? "text-fg" : "text-dim"}>{ROLE_RING_LABEL[event.role]}</span>
      <span className="text-fg">{event.su}</span>
      <span className="text-dim">{event.c}</span>
      <span className="flex items-center gap-1">
        <span className="num w-4 text-right text-dim">{padZero(event.sev, 2)}</span>
        <span className="text-dimmer">{bar(event.sev / 100, 8)}</span>
      </span>
      <span className="text-dimmer">{event.gate}</span>
      <span className={DISPOSITION_TEXT[event.dsp]}>{event.dsp}</span>
      <span className="truncate text-dimmer" title={GATE_LABEL[event.gate]}>
        {CODE_LABEL[event.c]}
      </span>
    </div>
  );
}

export default function EventStream(): JSX.Element {
  const state = useConsole();
  const { ring, seq } = useEventRing();
  const scroller = useRef<HTMLDivElement>(null);
  const [follow, setFollow] = useState(true);
  const [viewport, setViewport] = useState({ top: 0, height: 0 });

  // Measure the viewport once, then keep measuring it as panels are resized.
  useLayoutEffect(() => {
    const { current: el } = scroller;
    if (el === null) return;
    const measure = (): void => {
      const { clientHeight: height, scrollTop: top } = el;
      setViewport((prev) => (prev.height === height && prev.top === top ? prev : { top, height }));
    };
    measure();
    const observer = new ResizeObserver(measure);
    observer.observe(el);
    return () => observer.disconnect();
  }, []);

  /**
   * Pin to the newest row while following, and update the rendered window in the SAME
   * layout pass.
   *
   * Scroll events fire after paint. Pinning the scroll position and then waiting for a
   * scroll event to tell us where we ended up paints one frame whose rows sit at the
   * previous window — and because a live arbiter commits every frame, that lag would
   * leave the stream looking blank almost continuously. The bottom offset is known
   * arithmetically, so the window is set from the calculation rather than from the event.
   */
  useLayoutEffect(() => {
    const { current: el } = scroller;
    if (el === null) return;
    const { clientHeight: height } = el;

    if (!follow) {
      // Detached: the operator owns the position, and the scroll handler runs the window.
      const { scrollTop: top } = el;
      setViewport((prev) => (prev.top === top && prev.height === height ? prev : { top, height }));
      return;
    }

    const top = Math.max(0, ring.size * ROW_H - height);
    el.scrollTop = top;
    setViewport((prev) => (prev.top === top && prev.height === height ? prev : { top, height }));
  }, [seq, follow, ring, viewport.height]);

  const first = Math.max(0, Math.floor(viewport.top / ROW_H) - OVERSCAN);
  const last = Math.min(
    ring.size,
    Math.ceil((viewport.top + Math.max(viewport.height, ROW_H)) / ROW_H) + OVERSCAN,
  );

  const rows: JSX.Element[] = [];
  for (let i = first; i < last; i += 1) {
    const event = ring.at(i);
    if (event === undefined) continue;
    rows.push(<EventRow key={event.q} event={event} top={i * ROW_H} />);
  }

  const { counters } = state;
  const linkReason = state.reason === "" ? "" : ` · ${state.reason}`;

  return (
    <section className="flex min-h-0 flex-1 flex-col bg-panel">
      <header className="flex h-[22px] shrink-0 items-center justify-between border-b border-line px-2 text-[10px] uppercase tracking-[0.18em]">
        <span className="flex items-center gap-2">
          <span className="text-fg">ADJUDICATED EVENT STREAM</span>
          <span className="text-dimmer">
            {first}–{last} / {ring.size}
          </span>
        </span>
        <span className="flex items-center gap-3">
          <span className={ring.dropped > 0 ? "text-pending" : "text-dimmer"}>
            RETAINED {compact(ring.size)} · DISCARDED {compact(ring.dropped)}
          </span>
          <button
            type="button"
            className="px-1 text-[10px] uppercase"
            onClick={() => {
              setFollow(true);
              const { current: el } = scroller;
              if (el !== null) el.scrollTop = ring.size * ROW_H;
            }}
          >
            {follow ? "[ PINNED ]" : "[ RESUME ]"}
          </button>
        </span>
      </header>

      <div className={`${GRID} shrink-0 border-b border-line py-1 text-[10px] uppercase tracking-[0.12em] text-dimmer`}>
        <span>SEQ</span>
        <span>ARBITER TIME</span>
        <span>AGENT</span>
        <span>RING</span>
        <span>SUBJECT</span>
        <span>CODE</span>
        <span>SEVERITY</span>
        <span>GATE</span>
        <span>DISP</span>
        <span>EVIDENCE</span>
      </div>

      <div
        ref={scroller}
        className="min-h-0 flex-1 overflow-y-scroll"
        onScroll={(event) => {
          const { currentTarget: el } = event;
          const atBottom = el.scrollTop + el.clientHeight >= el.scrollHeight - ROW_H;
          setFollow(atBottom);
          const { scrollTop: top, clientHeight: height } = el;
          setViewport((prev) => (prev.top === top && prev.height === height ? prev : { top, height }));
        }}
      >
        {ring.size === 0 ? (
          <p className="px-2 py-3 text-[11px] text-dimmer">
            {state.link === "LIVE"
              ? "stream attached · no adjudicated samples yet"
              : `stream ${state.link.toLowerCase()}${linkReason}`}
          </p>
        ) : (
          <div className="relative" style={{ height: ring.size * ROW_H }}>
            {rows}
          </div>
        )}
      </div>

      <footer className="flex h-[20px] shrink-0 items-center justify-between border-t border-line px-2 text-[10px] text-dimmer">
        <span>
          ARBITER ACCEPTED {counters === null ? "—" : compact(counters.rx)} · REFUSED{" "}
          {counters === null ? "—" : compact(counters.rej)}
        </span>
        <span className="num">
          ROW {ROW_H}px · {last - first} NODES · BUFFER {ring.capacity.toLocaleString("en-US")}
        </span>
      </footer>
    </section>
  );
}
