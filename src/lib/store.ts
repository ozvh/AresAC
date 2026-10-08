/**
 * Telemetry store — the component that must survive thousands of samples per second.
 *
 * THE CONSTRAINT. A naive console renders once per received event. At 3,000 events
 * per second that is 3,000 React commits per second, which is a self-inflicted denial
 * of service on the operator's machine — and this console deliberately runs beside a
 * game, where a stolen frame is a stolen frame.
 *
 * THE DESIGN.
 *  - Socket frames are appended to plain arrays and a bounded ring. No React work.
 *  - A single requestAnimationFrame callback commits: it folds the queued events into
 *    the ring, swaps one immutable state object and notifies subscribers exactly once.
 *    Event rate therefore cannot exceed one render per display frame, and a burst of
 *    5,000 events costs one commit.
 *  - The event ring is fixed capacity. It discards its oldest entries and counts the
 *    loss, which is the honest behaviour: an operator can be told that 12,004 older
 *    frames were dropped, but cannot be shown a history that was silently truncated.
 *  - Components read the ring by index. Rendering is windowed by the consumer, so the
 *    visible row count — not the buffer size — drives the work per commit.
 */
import { useSyncExternalStore } from "react";
import {
  LIMITS,
  decodeFrame,
  type ChainView,
  type GateStageView,
  type LedgerView,
  type PublicCounters,
  type PublicEvent,
  type PublicSubject,
  type PublicTuning,
} from "@shared/protocol";
import { fetchSnapshot } from "./api";

export type LinkState = "IDLE" | "CONNECTING" | "LIVE" | "RESET" | "DOWN";

/** Fixed-capacity ring of adjudicated events, oldest-first by index. */
export class EventRing {
  readonly capacity: number;
  #buf: Array<PublicEvent | undefined>;
  #head = 0;
  #size = 0;
  dropped = 0;
  received = 0;

  constructor(capacity: number) {
    this.capacity = capacity;
    this.#buf = new Array<PublicEvent | undefined>(capacity);
  }

  push(event: PublicEvent): void {
    this.received += 1;
    if (this.#size === this.capacity) {
      this.#buf[this.#head] = event;
      this.#head = (this.#head + 1) % this.capacity;
      this.dropped += 1;
      return;
    }
    this.#buf[(this.#head + this.#size) % this.capacity] = event;
    this.#size += 1;
  }

  at(index: number): PublicEvent | undefined {
    if (index < 0 || index >= this.#size) return undefined;
    return this.#buf[(this.#head + index) % this.capacity];
  }

  get size(): number {
    return this.#size;
  }

  clear(): void {
    this.#buf = new Array<PublicEvent | undefined>(this.capacity);
    this.#head = 0;
    this.#size = 0;
  }
}

export type ConsoleState = {
  readonly link: LinkState;
  readonly reason: string;
  readonly counters: PublicCounters | null;
  readonly corpus: number;
  readonly tuning: PublicTuning | null;
  readonly gates: readonly GateStageView[];
  readonly ledger: readonly LedgerView[];
  readonly chain: ChainView | null;
  readonly agents: number;
  readonly uptimeMs: number;
  readonly paused: boolean;
  readonly scenario: string | null;
  readonly rate: number;
  readonly subjects: readonly PublicSubject[];
  readonly events: EventRing;
  /** Monotonic count of events folded into the ring. Changes every commit that adds any. */
  readonly eventSeq: number;
  readonly frames: number;
  readonly snapshots: number;
  readonly resets: number;
  readonly lastFrameAt: number;
  readonly selected: string | null;
  readonly notice: string;
};

const STATE_SEED: ConsoleState = {
  link: "IDLE",
  reason: "",
  counters: null,
  corpus: 0,
  tuning: null,
  gates: [],
  ledger: [],
  chain: null,
  agents: 0,
  uptimeMs: 0,
  paused: false,
  scenario: null,
  rate: 0,
  subjects: [],
  events: new EventRing(LIMITS.consoleRing),
  eventSeq: 0,
  frames: 0,
  snapshots: 0,
  resets: 0,
  lastFrameAt: 0,
  selected: null,
  notice: "",
};

/** A frame is overdue if the arbiter's own snapshot cadence (500 ms) is missed by this much. */
const STALE_FRAME_MS = 4_000;
const RECONNECT_MS = 2_000;

class Telemetry {
  readonly #listeners = new Set<() => void>();
  readonly #ring = new EventRing(LIMITS.consoleRing);
  #queued: PublicEvent[] = [];
  #state: ConsoleState = { ...STATE_SEED, events: this.#ring };
  #source: EventSource | null = null;
  #frameHandle: number | null = null;
  #reconnectHandle: number | null = null;
  #ticker: number | null = null;
  #eventSeq = 0;
  #frames = 0;
  #snapshots = 0;
  #resets = 0;
  #lastFrameAt = 0;
  #link: LinkState = "IDLE";
  #reason = "";
  #selected: string | null = null;
  #notice = "";
  #counters: PublicCounters | null = null;
  #corpus = 0;
  #tuning: PublicTuning | null = null;
  #gates: GateStageView[] = [];
  #ledger: LedgerView[] = [];
  #chain: ChainView | null = null;
  #agents = 0;
  #uptimeMs = 0;
  #paused = false;
  #scenario: string | null = null;
  #rate = 0;
  /** Arbiter boot time, parsed once from the counter payload rather than per frame. */
  #bootEpoch = 0;
  #subjects: PublicSubject[] = [];
  #started = false;

  subscribe = (listener: () => void): (() => void) => {
    this.#listeners.add(listener);
    return () => {
      this.#listeners.delete(listener);
    };
  };

  getSnapshot = (): ConsoleState => this.#state;

  start(): void {
    if (this.#started) return;
    this.#started = true;
    void this.resync();
    this.#connect();
    // One tick per second: advances the "age of last frame" readout and lets the
    // link state degrade to STALE on its own rather than waiting for a socket error.
    this.#ticker = window.setInterval(() => {
      const stale = this.#link === "LIVE" && Date.now() - this.#lastFrameAt > STALE_FRAME_MS;
      if (stale) {
        this.#link = "DOWN";
        this.#reason = "no frame within staleness budget";
        this.#commit();
      } else {
        this.#commit();
      }
    }, 1_000);
  }

  stop(): void {
    this.#started = false;
    this.#source?.close();
    this.#source = null;
    if (this.#frameHandle !== null) window.cancelAnimationFrame(this.#frameHandle);
    if (this.#reconnectHandle !== null) window.clearTimeout(this.#reconnectHandle);
    if (this.#ticker !== null) window.clearInterval(this.#ticker);
    this.#frameHandle = null;
    this.#reconnectHandle = null;
    this.#ticker = null;
  }

  select(tag: string | null): void {
    if (this.#selected === tag) return;
    this.#selected = tag;
    this.#commit();
  }

  notify(text: string): void {
    this.#notice = text;
    this.#commit();
  }

  /** Take a full state sync. Used at start-up and after any stream reset. */
  async resync(): Promise<void> {
    const snap = await fetchSnapshot();
    if (snap === null) {
      if (this.#link !== "LIVE") {
        this.#link = "DOWN";
        this.#reason = "arbiter unreachable";
        this.#commit();
      }
      return;
    }
    this.#setCounters(snap.counters);
    this.#corpus = snap.corpus;
    this.#tuning = snap.tuning;
    this.#gates = snap.gates;
    this.#ledger = snap.ledger;
    this.#chain = snap.chain;
    this.#agents = snap.agents;
    this.#uptimeMs = snap.uptimeMs;
    this.#paused = snap.paused;
    this.#scenario = snap.scenario;
    this.#rate = snap.rate;
    this.#subjects = snap.subjects;
    this.#snapshots += 1;
    this.#commit();
  }

  #connect(): void {
    if (this.#source !== null) this.#source.close();
    this.#link = "CONNECTING";
    this.#reason = "";
    this.#commit();

    const source = new EventSource("/v1/stream");
    this.#source = source;

    source.onopen = () => {
      this.#link = "LIVE";
      this.#reason = "";
      this.#commit();
    };

    source.addEventListener("f", (event: MessageEvent<string>) => {
      this.#frames += 1;
      this.#lastFrameAt = Date.now();
      const frame = decodeFrame(event.data);
      if (frame === null) return;
      this.#apply(frame);
    });

    source.onerror = () => {
      // EventSource retries by itself with the server's stated backoff and replays
      // Last-Event-ID. Only a closed stream needs us to rebuild it.
      if (source.readyState === EventSource.CLOSED) {
        this.#link = "DOWN";
        this.#reason = "stream closed by the arbiter";
        this.#commit();
        this.#scheduleReconnect();
      } else if (this.#link === "LIVE") {
        this.#link = "CONNECTING";
        this.#reason = "reconnecting";
        this.#commit();
      }
    };
  }

  #setCounters(next: PublicCounters): void {
    this.#counters = next;
    if (this.#bootEpoch === 0) {
      const parsed = Date.parse(next.boot);
      if (Number.isFinite(parsed)) this.#bootEpoch = parsed;
    }
  }

  #scheduleReconnect(): void {
    if (this.#reconnectHandle !== null) return;
    this.#reconnectHandle = window.setTimeout(() => {
      this.#reconnectHandle = null;
      if (this.#started) void this.resync();
      if (this.#started) this.#connect();
    }, RECONNECT_MS);
  }

  #apply(frame: { k: string; [key: string]: unknown }): void {
    if (frame.k === "E") {
      const batch = frame["batch"] as readonly PublicEvent[] | undefined;
      if (batch === undefined) return;
      for (const event of batch) this.#queued.push(event);
      // A single unrendered burst is bounded: a hostile upstream cannot force this
      // console to hold an unbounded queue between frames.
      if (this.#queued.length > 20_000) this.#queued.splice(0, this.#queued.length - 20_000);
      this.#scheduleCommit();
      return;
    }
    if (frame.k === "S") {
      const subjects = frame["subj"] as readonly PublicSubject[] | undefined;
      const counters = frame["ctr"] as PublicCounters | undefined;
      if (subjects !== undefined) this.#subjects = subjects as PublicSubject[];
      if (counters !== undefined) this.#setCounters(counters);
      const { corpus } = frame;
      if (typeof corpus === "number") this.#corpus = corpus;
      if (this.#link !== "LIVE") this.#link = "LIVE";
      this.#scheduleCommit();
      return;
    }
    if (frame.k === "R") {
      // The arbiter has told us our history has a hole in it. Drop it and resync
      // rather than rendering a stream with a plausible-looking gap.
      this.#resets += 1;
      this.#reason = String(frame["reason"] ?? "stream reset");
      this.#link = "RESET";
      this.#queued.length = 0;
      this.#ring.clear();
      this.#commit();
      void this.resync();
      this.#scheduleCommit();
    }
  }

  #scheduleCommit(): void {
    if (this.#frameHandle !== null) return;
    this.#frameHandle = window.requestAnimationFrame(() => {
      this.#frameHandle = null;
      this.#commit();
    });
  }

  #commit(): void {
    if (this.#queued.length > 0) {
      const batch = this.#queued;
      this.#queued = [];
      for (const event of batch) {
        this.#ring.push(event);
        this.#eventSeq += 1;
      }
    }
    const counters = this.#counters;
    this.#state = {
      link: this.#link,
      reason: this.#reason,
      counters,
      corpus: this.#corpus,
      tuning: this.#tuning,
      gates: this.#gates,
      ledger: this.#ledger,
      chain: this.#chain,
      agents: this.#agents,
      uptimeMs: this.#bootEpoch === 0 ? this.#uptimeMs : Math.max(0, Date.now() - this.#bootEpoch),
      paused: this.#paused,
      scenario: this.#scenario,
      rate: this.#rate,
      subjects: this.#subjects,
      events: this.#ring,
      eventSeq: this.#eventSeq,
      frames: this.#frames,
      snapshots: this.#snapshots,
      resets: this.#resets,
      lastFrameAt: this.#lastFrameAt,
      selected: this.#selected,
      notice: this.#notice,
    };
    for (const listener of this.#listeners) listener();
  }
}

export const telemetry = new Telemetry();

export function useConsole(): ConsoleState {
  return useSyncExternalStore(telemetry.subscribe, telemetry.getSnapshot, telemetry.getSnapshot);
}

/** Ring buffer of adjudicated events plus the counters that describe its health. */
export function useEventRing(): { ring: EventRing; seq: number } {
  const state = useConsole();
  return { ring: state.events, seq: state.eventSeq };
}
