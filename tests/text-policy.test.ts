import assert from "node:assert/strict";
import { test } from "node:test";
import { hasForbiddenControl } from "../server/text-policy.ts";

test("every ASCII control is refused in headers and filenames; notes allow only LF", () => {
  for (let code = 0; code < 128; code += 1) {
    const value = `before${String.fromCharCode(code)}after`;
    const control = code <= 31 || code === 127;
    assert.equal(hasForbiddenControl(value), control, `strict ASCII ${code}`);
    assert.equal(hasForbiddenControl(value, true), control && code !== 10, `note ASCII ${code}`);
  }
});

test("ordinary Unicode and multiline notes retain their content policy", () => {
  assert.equal(hasForbiddenControl("résumé — 玩家 🎮"), false);
  assert.equal(hasForbiddenControl("first\nsecond", true), false);
  assert.equal(hasForbiddenControl("first\nsecond"), true);
  assert.equal(hasForbiddenControl("first\r\nsecond", true), true);
  assert.equal(hasForbiddenControl("first\nsecond\0", true), true);
});
