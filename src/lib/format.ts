/**
 * Fixed-width readouts.
 *
 * Every value rendered in this console occupies a predictable character cell.
 * A counter crossing 9 -> 10 must not move anything to its right, so nothing here
 * returns a naturally-sized string: widths are explicit and callers pass them.
 */

export function pad(value: number, width: number): string {
  const whole = Number.isFinite(value) ? Math.trunc(value) : 0;
  return String(whole).padStart(width, " ");
}

export function padZero(value: number, width: number): string {
  const whole = Number.isFinite(value) ? Math.trunc(value) : 0;
  return String(whole).padStart(width, "0");
}

/** Compact magnitude: 1234 -> 1.2k, 1250000 -> 1.2M. Always 4 cells or fewer. */
export function compact(value: number): string {
  if (!Number.isFinite(value)) return "—";
  const abs = Math.abs(value);
  if (abs < 1_000) return String(Math.trunc(value));
  if (abs < 1_000_000) return `${(value / 1_000).toFixed(1)}k`;
  if (abs < 1_000_000_000) return `${(value / 1_000_000).toFixed(1)}M`;
  return `${(value / 1_000_000_000).toFixed(1)}G`;
}

export function pct(value: number, decimals = 1): string {
  if (!Number.isFinite(value)) return "—";
  return `${(value * 100).toFixed(decimals)}%`;
}

export function score(value: number): string {
  if (!Number.isFinite(value)) return "0.00";
  return value.toFixed(2);
}

/** Wall clock with millisecond resolution, fixed width. */
export function clock(ts: number): string {
  const d = new Date(ts);
  return (
    `${padZero(d.getHours(), 2)}:${padZero(d.getMinutes(), 2)}:${padZero(d.getSeconds(), 2)}.` +
    padZero(d.getMilliseconds(), 3)
  );
}

/** Duration as a fixed-width, unit-suffixed cell. */
export function duration(ms: number): string {
  if (!Number.isFinite(ms) || ms < 0) return "—";
  if (ms < 1_000) return `${Math.round(ms)}ms`;
  if (ms < 60_000) return `${(ms / 1_000).toFixed(1)}s`;
  if (ms < 3_600_000) return `${Math.floor(ms / 60_000)}m${padZero(Math.floor((ms % 60_000) / 1_000), 2)}`;
  return `${Math.floor(ms / 3_600_000)}h${padZero(Math.floor((ms % 3_600_000) / 60_000), 2)}`;
}

export function uptime(ms: number): string {
  const total = Math.max(0, Math.floor(ms / 1000));
  const h = Math.floor(total / 3600);
  const m = Math.floor((total % 3600) / 60);
  const s = total % 60;
  return `${padZero(h, 2)}:${padZero(m, 2)}:${padZero(s, 2)}`;
}

/** A 12-hex subject digest, split for legibility without changing its width. */
export function group12(tag: string): string {
  return `${tag.slice(0, 4)} ${tag.slice(4, 8)} ${tag.slice(8, 12)}`;
}

/** A fixed-width horizontal bar. Built from block glyphs, not from a styled div. */
export function bar(fraction: number, cells: number): string {
  const clamped = Number.isFinite(fraction) ? Math.min(1, Math.max(0, fraction)) : 0;
  const filled = Math.round(clamped * cells);
  return "█".repeat(filled) + "░".repeat(Math.max(0, cells - filled));
}
