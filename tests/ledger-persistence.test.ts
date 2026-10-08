/**
 * Ledger durability suite.
 *
 * The chain is only evidence if it outlives the process that built it, so these tests are
 * written from the attacker's side of a *restart*: seal records, stop, hand the file to
 * the arbiter again, and assert three things — that the sequence and head resume rather
 * than reset, that a record rewritten between the two runs is named as broken, and that
 * the engine refuses to rewrite one through its own connection at all.
 *
 * A test that only appended and re-read would pass for a ledger that merely wrote to a
 * log file; the assertions that matter are the ones that fail when recovery is skipped.
 */
import assert from "node:assert/strict";
import { mkdtemp } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { test } from "node:test";
import { DatabaseSync } from "node:sqlite";
import { bootstrap } from "../server/bootstrap.ts";
import { Store } from "../server/db.ts";
import { Ledger } from "../server/ledger.ts";

const NOW = 1_700_000_000_000;

async function ledgerFile(): Promise<string> {
  const dir = await mkdtemp(path.join(os.tmpdir(), "ares-ledger-"));
  return path.join(dir, "ledger.db");
}

test("the chain survives a restart and the sequence continues across it", async () => {
  const file = await ledgerFile();

  const store1 = new Store({ file, now: () => NOW });
  const ledger1 = new Ledger({ store: store1 });
  ledger1.append("BOOT", "-", "agents=3", NOW);
  ledger1.append("VERDICT", "abcdef123456", "FLAGGED/CONVICT/0.95", NOW + 1);
  const head1 = ledger1.head;
  assert.equal(ledger1.length, 2);
  store1.close();

  const store2 = new Store({ file, now: () => NOW });
  const ledger2 = new Ledger({ store: store2 });
  assert.equal(ledger2.recovery?.ok, true, "a clean chain must verify on boot");
  assert.equal(ledger2.recovery?.records, 2);
  assert.equal(ledger2.length, 2, "the sequence resumes from the stored chain, not from zero");
  assert.equal(ledger2.head, head1, "the running head is recovered, not reset to genesis");

  // The next sealed record links to the recovered head, which is what makes the stored
  // chain a single chain across the restart rather than two chains that agree on nothing.
  const next = ledger2.append("RELEASE", "abcdef123456", "PENDING/VETO", NOW + 2);
  assert.equal(next.seq, 3);
  assert.equal(next.prev, head1);
  assert.equal(ledger2.verify().ok, true);

  // The retained window is hydrated from storage too, so the console shows continuity
  // after a restart instead of an empty tail.
  assert.deepEqual(
    ledger2.tail(10).map((r) => r.seq),
    [1, 2, 3],
  );
  store2.close();
});

test("a record rewritten between runs is detected after the restart, at its sequence", async () => {
  const file = await ledgerFile();

  const store1 = new Store({ file, now: () => NOW });
  const ledger1 = new Ledger({ store: store1 });
  ledger1.append("BOOT", "-", "agents=3", NOW);
  ledger1.append("VERDICT", "abcdef123456", "FLAGGED/CONVICT/0.95", NOW + 1);
  ledger1.append("VERDICT", "abcdef123456", "CLEAN/NONE/0.00", NOW + 2);
  store1.close();

  // An intruder with file access, standing in for an operator at a sqlite prompt or a
  // restore tool: the append-only trigger is dropped, then a sealed verdict is inflated.
  const intruder = new DatabaseSync(file);
  intruder.exec("DROP TRIGGER ledger_records_no_update");
  intruder.exec("UPDATE ledger_records SET dt = 'FLAGGED/CONVICT/0.99' WHERE seq = 2");
  intruder.close();

  const store2 = new Store({ file, now: () => NOW });
  const ledger2 = new Ledger({ store: store2 });
  assert.equal(ledger2.recovery?.ok, false, "a rewritten record must fail verification on boot");
  assert.equal(ledger2.recovery?.at, 2, "the first record whose link no longer verifies is named");
  assert.equal(ledger2.status().broken, true);
  assert.equal(ledger2.status().brokenAt, 2);

  // Continuing to seal does not launder the tamper: the break stays reported.
  ledger2.append("RELEASE", "abcdef123456", "PENDING/VETO", NOW + 3);
  assert.equal(ledger2.status().broken, true);
  assert.equal(ledger2.status().brokenAt, 2);
  store2.close();
});

test("the ledger table is append-only at the engine level", async () => {
  const file = await ledgerFile();

  const store1 = new Store({ file, now: () => NOW });
  const ledger1 = new Ledger({ store: store1 });
  ledger1.append("BOOT", "-", "agents=3", NOW);
  store1.close();

  // A row must be present for the trigger to fire: an UPDATE or DELETE that matches no
  // row raises nothing, so an empty table would make this test prove the opposite of
  // what it claims. The row is seeded above on purpose.
  const intruder = new DatabaseSync(file);
  assert.throws(() => intruder.exec("UPDATE ledger_records SET dt = 'rewritten'"), /append-only/);
  assert.throws(() => intruder.exec("DELETE FROM ledger_records"), /append-only/);
  intruder.close();
});

test("a restarted arbiter resumes the chain from its own store and warns on a tamper", async () => {
  const dir = await mkdtemp(path.join(os.tmpdir(), "ares-boot-"));
  const file = path.join(dir, "boot.db");

  const first = bootstrap({ dbFile: file, uploadDir: path.join(dir, "up-1"), env: {}, now: () => NOW });
  first.ledger.append("VERDICT", "abcdef123456", "FLAGGED/CONVICT/0.95", NOW);
  const head = first.ledger.head;
  first.store.close();

  const second = bootstrap({ dbFile: file, uploadDir: path.join(dir, "up-2"), env: {}, now: () => NOW });
  assert.equal(second.ledger.recovery?.ok, true);
  assert.equal(second.ledger.head, head, "the composition root must hand the store to the ledger");
  assert.equal(second.ledger.length, 1);
  assert.ok(
    !second.notices.some((n) => /ledger/i.test(n)),
    "a clean recovery must not raise a ledger warning",
  );

  // The real boot path seals its own BOOT record onto the recovered chain.
  second.runtime.start();
  second.runtime.stop();
  assert.equal(second.ledger.length, 2);
  assert.equal(second.ledger.tail(5)[1]?.kind, "BOOT");
  assert.equal(second.ledger.verify().ok, true);

  // Now rewrite a stored record and boot a third time: the operator is told, by name.
  second.store.close();
  const intruder = new DatabaseSync(file);
  intruder.exec("DROP TRIGGER ledger_records_no_update");
  intruder.exec("UPDATE ledger_records SET su = 'ffffffffffff' WHERE seq = 1");
  intruder.close();

  const third = bootstrap({ dbFile: file, uploadDir: path.join(dir, "up-3"), env: {}, now: () => NOW });
  assert.equal(third.ledger.status().broken, true);
  assert.ok(
    third.notices.some((n) => /ledger failed verification at record 1/.test(n)),
    "the boot notice must name the record that stopped verifying",
  );
  third.store.close();
});
