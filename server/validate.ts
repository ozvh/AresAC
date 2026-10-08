/**
 * Ingest parsing. The only boundary at which hostile bytes become structured data.
 *
 * Rules enforced here, before any other component can observe the value:
 *  - byte ceiling checked before JSON.parse; an oversized body is never parsed
 *  - closed key set: an event carrying an unexpected key is rejected outright, so
 *    no unmodelled field can ride along into the scoring path
 *  - every field is a bounded primitive; no nested objects, no arrays, no coercion
 *  - numeric fields are range-checked, so no NaN/Infinity/negative-sequence trick
 *    can corrupt the monotonic counters behind them
 */
import {
  EVIDENCE_CODES,
  LIMITS,
  PROTOCOL_VERSION,
  type ApiErrorCode,
  type EvidenceCode,
  type IngestEvent,
  type RingId,
} from "../shared/protocol.ts";

export type ParseFailure = { readonly ok: false; readonly code: ApiErrorCode; readonly msg: string };
export type ParseSuccess = { readonly ok: true; readonly events: readonly IngestEvent[] };
export type ParseResult = ParseSuccess | ParseFailure;

const KEYS = ["v", "a", "k", "s", "t", "r", "c", "m"] as const;
const HEX16 = /^[0-9a-f]{16}$/;
const HEX32 = /^[0-9a-f]{32}$/;
const EVIDENCE_SET: ReadonlySet<string> = new Set<string>(EVIDENCE_CODES);
const RINGS: ReadonlySet<number> = new Set<number>([0, 3, -1]);

const MAX_SEQ = 4_294_967_295;
const MAX_CLOCK = 281_474_976_710_655; // 2^48 - 1
const MAX_MEASUREMENT = 1_000_000;

function fail(code: ApiErrorCode, msg: string): ParseFailure {
  return { ok: false, code, msg };
}

function isPlainObject(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function readEvent(value: unknown, index: number): IngestEvent | ParseFailure {
  if (!isPlainObject(value)) return fail("SCHEMA", `event[${index}] is not an object`);

  const keys = Object.keys(value);
  if (keys.length !== KEYS.length) return fail("SCHEMA", `event[${index}] key count ${keys.length}`);
  for (const k of KEYS) {
    if (!Object.hasOwn(value, k)) return fail("SCHEMA", `event[${index}] missing ${k}`);
  }
  if (keys.length !== new Set(keys).size) return fail("SCHEMA", `event[${index}] duplicate keys`);

  const v = value["v"];
  const a = value["a"];
  const k = value["k"];
  const s = value["s"];
  const t = value["t"];
  const r = value["r"];
  const c = value["c"];
  const m = value["m"];

  if (v !== PROTOCOL_VERSION) return fail("SCHEMA", `event[${index}] protocol ${String(v)}`);
  if (typeof a !== "string" || !HEX16.test(a)) return fail("SCHEMA", `event[${index}] bad agent id`);
  if (typeof k !== "string" || !HEX32.test(k)) return fail("SCHEMA", `event[${index}] bad subject digest`);
  if (typeof c !== "string" || !EVIDENCE_SET.has(c)) return fail("SCHEMA", `event[${index}] unknown code`);
  if (typeof r !== "number" || !RINGS.has(r)) return fail("SCHEMA", `event[${index}] bad ring`);

  if (typeof s !== "number" || !Number.isInteger(s) || s < 1 || s > MAX_SEQ) {
    return fail("SCHEMA", `event[${index}] sequence out of range`);
  }
  if (typeof t !== "number" || !Number.isInteger(t) || t < 0 || t > MAX_CLOCK) {
    return fail("SCHEMA", `event[${index}] clock out of range`);
  }
  if (typeof m !== "number" || !Number.isFinite(m) || Math.abs(m) > MAX_MEASUREMENT) {
    return fail("SCHEMA", `event[${index}] measurement out of range`);
  }

  return {
    v: PROTOCOL_VERSION,
    a,
    k,
    s,
    t,
    r: r as RingId,
    c: c as EvidenceCode,
    m,
  };
}

export function parseIngest(raw: string): ParseResult {
  if (raw.length > LIMITS.bodyBytes) return fail("TOO_LARGE", `body ${raw.length} > ${LIMITS.bodyBytes}`);
  if (raw.length === 0) return fail("SCHEMA", "empty body");

  let parsed: unknown;
  try {
    parsed = JSON.parse(raw);
  } catch {
    return fail("MALFORMED", "body is not JSON");
  }

  const list: unknown[] = Array.isArray(parsed) ? parsed : [parsed];
  if (list.length === 0) return fail("SCHEMA", "empty batch");
  if (list.length > LIMITS.batchMax) return fail("SCHEMA", `batch ${list.length} > ${LIMITS.batchMax}`);

  const events: IngestEvent[] = [];
  for (let i = 0; i < list.length; i += 1) {
    const read = readEvent(list[i], i);
    if ("ok" in read) return read;
    events.push(read);
  }
  return { ok: true, events };
}
