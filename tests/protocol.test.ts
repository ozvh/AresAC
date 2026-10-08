/**
 * The console parses everything the arbiter sends it. It is a display surface in a
 * hostile room, so it treats even its own upstream as untrusted input: a frame that
 * does not match the contract is dropped rather than rendered.
 */
import assert from "node:assert/strict";
import { test } from "node:test";
import { decodeFrame, isEvidenceCode, isPublicEvent, isPublicSubject, isRole } from "../shared/protocol.ts";

function event(overrides: Record<string, unknown> = {}): Record<string, unknown> {
  return {
    q: 1,
    ts: 1_700_000_000_000,
    ag: "01234567",
    role: "UMON",
    su: "abcdefabcdef",
    c: "X3",
    sev: 92,
    gate: "G1",
    dsp: "DENY",
    ...overrides,
  };
}

test("malformed, empty and non-JSON frames decode to null rather than throwing", () => {
  assert.equal(decodeFrame(""), null);
  assert.equal(decodeFrame("not json"), null);
  assert.equal(decodeFrame("[]"), null);
  assert.equal(decodeFrame("null"), null);
  assert.equal(decodeFrame('{"k":"E"}'), null);
  assert.equal(decodeFrame('{"k":"E","batch":"nope"}'), null);
  assert.equal(decodeFrame('{"k":"S"}'), null);
  assert.equal(decodeFrame('{"k":"???"}'), null);
});

test("an event frame keeps only well-formed events", () => {
  const frame = decodeFrame(
    JSON.stringify({
      k: "E",
      batch: [
        event(),
        event({ c: "ZZ" }),
        event({ sev: 101 }),
        event({ sev: -1 }),
        event({ role: "ROOT" }),
        event({ gate: "G9" }),
        event({ q: Number.NaN }),
        event({ ts: "1700000000000" }),
        null,
        "string",
        event({ c: "X1" }),
      ],
    }),
  );
  assert.ok(frame);
  assert.equal(frame.k, "E");
  if (frame.k !== "E") return;
  assert.equal(frame.batch.length, 2, "only the two well-formed events survive");
  assert.deepEqual(
    frame.batch.map((e) => e.c),
    ["X3", "X1"],
  );
});

test("a subject frame keeps only well-formed subjects and tolerates a missing corpus field", () => {
  const frame = decodeFrame(
    JSON.stringify({
      k: "S",
      ctr: { rx: 1 },
      subj: [
        { su: "aaaaaaaaaaaa", vd: "FLAGGED", rm: 3, sc: 0.91, dw: 1500, st: "CONVICT", ct: true, n: 12, last: 1 },
        { su: "bbbbbbbbbbbb", vd: "MAYBE", rm: 3, sc: 0.5, dw: 0, st: "NONE", ct: false, n: 1, last: 1 },
        { su: "cccccccccccc", vd: "CLEAN", rm: 8, sc: 0.1, dw: 0, st: "NONE", ct: false, n: 1, last: 1 },
        { su: "dddddddddddd", vd: "CLEAN", rm: 0, sc: 0.1, dw: 0, st: "SUPPRESS", ct: false, n: 1, last: 1 },
        { su: "eeeeeeeeeeee", vd: "CLEAN", rm: 0, sc: 0.1, dw: 0, st: "BOGUS", ct: false, n: 1, last: 1 },
      ],
    }),
  );
  assert.ok(frame);
  if (frame.k !== "S") throw new Error("expected a state frame");
  assert.equal(frame.subj.length, 2, "the verdict, mask and step bounds are all enforced");
  assert.equal(frame.corpus, 0, "a missing corpus count degrades to zero, not NaN");
});

test("the reset frame is surfaced with its reason", () => {
  const frame = decodeFrame(JSON.stringify({ k: "R", reason: "observer backpressure" }));
  assert.deepEqual(frame, { k: "R", reason: "observer backpressure" });
});

test("primitive guards reject near-misses", () => {
  assert.equal(isRole("umon"), false);
  assert.equal(isRole("UMON"), true);
  assert.equal(isEvidenceCode("X1"), true);
  assert.equal(isEvidenceCode("x1"), false);
  assert.equal(isEvidenceCode(null), false);
  assert.equal(isPublicEvent({}), false);
  assert.equal(isPublicSubject("subject"), false);
  const complete = { su: "a".repeat(12), vd: "CLEAN", rm: 0, sc: 0, dw: 0, st: "NONE", ct: false, n: 0, last: 0 };
  assert.equal(isPublicSubject(complete), true);
  const { last, ...missingOne } = complete;
  void last;
  assert.equal(isPublicSubject(missingOne), false, "a subject missing the activity stamp is not renderable");
});
