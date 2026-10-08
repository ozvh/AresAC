import assert from "node:assert/strict";
import { test } from "node:test";
import { aresEnvironment } from "../server/legacy-env.ts";

test("legacy deployment settings survive the rename and explicit Ares settings win", () => {
  const old = { ZEUS_DB: "old.db", ZEUS_SESSION_KEY: "retained-key", ARES_DB: "new.db" };
  const current = aresEnvironment(old);
  assert.equal(current["ARES_DB"], "new.db");
  assert.equal(current["ARES_SESSION_KEY"], "retained-key");
  assert.equal(Object.hasOwn(old, "ARES_SESSION_KEY"), false);
});
