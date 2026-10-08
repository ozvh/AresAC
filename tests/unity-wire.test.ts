import assert from "node:assert/strict";
import { existsSync, mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { spawnSync } from "node:child_process";
import { test } from "node:test";
import { canonicalEvent } from "../shared/protocol.ts";
import { demoAgentId, demoAgentKey, demoSign, demoSubject } from "../tools/demo-agents.ts";

const root = fileURLToPath(new URL("../", import.meta.url));
const compiler = path.join(process.env["WINDIR"] ?? "C:\\Windows", "Microsoft.NET", "Framework64", "v4.0.30319", "csc.exe");

test("compiled Unity wire keeps signing state immutable and matches arbiter protocol", {
  skip: process.platform !== "win32" || !existsSync(compiler) ? "requires Windows .NET Framework C# compiler" : false,
}, () => {
  const directory = mkdtempSync(path.join(tmpdir(), "ares-wire-"));
  try {
    const executable = path.join(directory, "wire-regression.exe");
    const compile = spawnSync(compiler, [
      "/nologo", `/out:${executable}`,
      path.join(root, "unity/Assets/Ares/Scripts/AresWire.cs"),
      path.join(root, "tests/fixtures/UnityWireRegression.cs"),
    ], { encoding: "utf8", timeout: 30_000, windowsHide: true });
    assert.equal(compile.status, 0, compile.error?.message ?? compile.stdout + compile.stderr);
    const run = spawnSync(executable, [], { encoding: "utf8", timeout: 10_000, windowsHide: true });
    assert.equal(run.status, 0, run.error?.message ?? run.stdout + run.stderr);
    const id = demoAgentId("KMOD", 1);
    const canonical = canonicalEvent({ v: 1, a: id, k: demoSubject("unity-demo-player"), s: 1, t: 1700000000000, r: 0, c: "X2", m: 1 });
    assert.deepEqual(run.stdout.trim().split(/\r?\n/), [id, canonical, demoSign(demoAgentKey(id), canonical)]);
  } finally {
    rmSync(directory, { recursive: true, force: true });
  }
});
