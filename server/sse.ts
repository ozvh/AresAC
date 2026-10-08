/**
 * Server-Sent Events broadcaster.
 *
 * Three properties this exists to guarantee, because a telemetry console that
 * silently loses frames is worse than one that admits it:
 *
 *  1. BOUNDED PER-SUBSCRIBER MEMORY. A subscriber that cannot keep up has its
 *     queue dropped *whole* and replaced by a single reset frame. The console
 *     resynchronises from /v1/snapshot rather than displaying a plausible but
 *     incomplete history. Silent gaps are the failure mode we refuse.
 *  2. REPLAY FOR RECONNECT. A bounded ring of recent frames, addressed by
 *     Last-Event-ID, so a dropped connection resumes without a full resync.
 *  3. NO THIRD-PARTY BUFFER DECIDES FOR US. Heartbeat comments keep intermediaries
 *     from reaping an idle stream; `X-Accel-Buffering: no` opts out of proxy
 *     buffering, which would otherwise coalesce frames and destroy the readout.
 */
import type { ServerResponse } from "node:http";

/** Frames queued per subscriber before the queue is collapsed into a reset. */
const MAX_QUEUE = 512;
const MAX_QUEUE_BYTES = 1024 * 1024;
const BLOCKED_TIMEOUT_MS = 30_000;

/** Concurrent observer ceiling. An observer is cheap, but not free. */
const MAX_SUBSCRIBERS = 32;

const HEARTBEAT_MS = 15_000;

type Subscriber = {
  readonly res: ServerResponse;
  readonly queue: string[];
  flushing: boolean;
  blocked: boolean;
  queuedBytes: number;
  blockedTimer: NodeJS.Timeout | null;
  closed: boolean;
  dropped: number;
};

type ReplayFrame = { readonly id: number; readonly chunk: string };

export class Broadcaster {
  readonly #subs = new Set<Subscriber>();
  readonly #replayDepth: number;
  #ring: ReplayFrame[] = [];
  #id = 0;
  #publishedFrames = 0;
  #droppedFrames = 0;
  #rejectedSubscribers = 0;
  #heartbeat: NodeJS.Timeout | null = null;

  constructor(replayDepth: number) {
    this.#replayDepth = replayDepth;
  }

  start(): void {
    if (this.#heartbeat !== null) return;
    this.#heartbeat = setInterval(() => {
      for (const sub of this.#subs) {
        // A heartbeat is never allowed to displace real data.
        if (sub.queue.length === 0) this.#enqueue(sub, `:hb ${Date.now()}\n\n`, false);
      }
    }, HEARTBEAT_MS);
    this.#heartbeat.unref();
  }

  stop(): void {
    if (this.#heartbeat !== null) {
      clearInterval(this.#heartbeat);
      this.#heartbeat = null;
    }
    for (const sub of this.#subs) {
      if (sub.blockedTimer !== null) clearTimeout(sub.blockedTimer);
      sub.res.end();
    }
    this.#subs.clear();
  }

  /** Serialise once, fan out to every subscriber. */
  publish(frame: unknown): void {
    this.#id += 1;
    this.#publishedFrames += 1;
    const chunk = `id: ${this.#id}\nevent: f\ndata: ${JSON.stringify(frame)}\n\n`;
    this.#ring.push({ id: this.#id, chunk });
    if (this.#ring.length > this.#replayDepth) {
      this.#ring.splice(0, this.#ring.length - this.#replayDepth);
    }
    for (const sub of this.#subs) this.#enqueue(sub, chunk, false);
  }

  /**
   * Attach an observer. `lastEventId` resumes from the replay ring when possible;
   * a value older than the ring forces an immediate reset frame so the console
   * knows to take a full snapshot.
   */
  subscribe(res: ServerResponse, lastEventId: number | null): { ok: true } | { ok: false; reason: string } {
    if (this.#subs.size >= MAX_SUBSCRIBERS) {
      this.#rejectedSubscribers += 1;
      return { ok: false, reason: "subscriber ceiling reached" };
    }

    res.writeHead(200, {
      "Content-Type": "text/event-stream; charset=utf-8",
      "Cache-Control": "no-store, no-cache, must-revalidate",
      Connection: "keep-alive",
      "X-Accel-Buffering": "no",
      "X-Content-Type-Options": "nosniff",
    });
    const sub: Subscriber = { res, queue: [], flushing: false, blocked: false, queuedBytes: 0, blockedTimer: null, closed: false, dropped: 0 };
    this.#subs.add(sub);

    res.on("close", () => {
      if (sub.blockedTimer !== null) clearTimeout(sub.blockedTimer);
      sub.closed = true;
      this.#subs.delete(sub);
    });
    res.on("error", () => {
      if (sub.blockedTimer !== null) clearTimeout(sub.blockedTimer);
      sub.closed = true;
      this.#subs.delete(sub);
    });
    // Undici/Node emit drain on the socket; resume pushing the backlog.
    res.on("drain", () => {
      if (sub.blockedTimer !== null) clearTimeout(sub.blockedTimer);
      sub.blockedTimer = null;
      sub.blocked = false;
      this.#flush(sub);
    });

    this.#enqueue(sub, `retry: 1500\n\n`, false);

    if (lastEventId !== null) {
      const oldest = this.#ring[0]?.id ?? this.#id + 1;
      if (lastEventId < oldest - 1) {
        this.#enqueue(
          sub,
          `event: f\ndata: ${JSON.stringify({ k: "R", reason: "replay window exceeded" })}\n\n`,
          true,
        );
      } else {
        for (const frame of this.#ring) {
          if (frame.id > lastEventId) this.#enqueue(sub, frame.chunk, false);
        }
      }
    }
    this.#flush(sub);
    return { ok: true };
  }

  #enqueue(sub: Subscriber, chunk: string, reset: boolean): void {
    if (sub.closed) return;
    if (reset) {
      sub.queue.length = 0;
      sub.queuedBytes = Buffer.byteLength(chunk);
      sub.queue.push(chunk);
      sub.dropped += 1;
      this.#droppedFrames += 1;
      this.#flush(sub);
      return;
    }
    if (sub.queue.length >= MAX_QUEUE || sub.queuedBytes + Buffer.byteLength(chunk) > MAX_QUEUE_BYTES) {
      // Collapse, do not silently truncate.
      sub.queue.length = 0;
      sub.queue.push(`event: f\ndata: ${JSON.stringify({ k: "R", reason: "observer backpressure" })}\n\n`);
      sub.queuedBytes = Buffer.byteLength(sub.queue[0]!);
      sub.dropped += 1;
      this.#droppedFrames += 1;
      this.#flush(sub);
      return;
    }
    sub.queue.push(chunk);
    sub.queuedBytes += Buffer.byteLength(chunk);
    this.#flush(sub);
  }

  #flush(sub: Subscriber): void {
    if (sub.flushing || sub.closed || sub.blocked) return;
    sub.flushing = true;
    for (;;) {
      const chunk = sub.queue.shift();
      if (chunk === undefined) break;
      sub.queuedBytes -= Buffer.byteLength(chunk);
      if (sub.res.writableEnded) {
        sub.closed = true;
        this.#subs.delete(sub);
        break;
      }
      if (!sub.res.write(chunk)) {
        sub.blocked = true;
        sub.blockedTimer = setTimeout(() => {
          sub.closed = true;
          sub.queue.length = 0;
          sub.queuedBytes = 0;
          this.#subs.delete(sub);
          sub.res.destroy();
        }, BLOCKED_TIMEOUT_MS);
        sub.blockedTimer.unref();
        break;
      }
    }
    sub.flushing = false;
  }

  get subscribers(): number {
    return this.#subs.size;
  }

  get published(): number {
    return this.#publishedFrames;
  }

  get dropped(): number {
    return this.#droppedFrames;
  }

  get rejected(): number {
    return this.#rejectedSubscribers;
  }
}
