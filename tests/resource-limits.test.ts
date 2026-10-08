import assert from "node:assert/strict";
import { test } from "node:test";
import { EventEmitter } from "node:events";
import type { ServerResponse } from "node:http";
import { mkdtemp, rm } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import type { AddressInfo } from "node:net";
import { bootstrap } from "../server/bootstrap.ts";
import { createArbiterServer } from "../server/http.ts";
import { Broadcaster } from "../server/sse.ts";
import { hashPassword, PASSWORD_WORK_LIMIT, PasswordWorkBusy } from "../server/passwords.ts";
import { UploadService, UploadStore } from "../server/uploads.ts";

class SlowResponse extends EventEmitter {
  chunks: string[] = [];
  writableEnded = false;
  slow = true;
  writeHead(): void {}
  write(chunk: string): boolean { this.chunks.push(chunk); return !this.slow; }
  end(): void { this.writableEnded = true; this.emit("close"); }
  destroy(): void { this.end(); }
}

test("SSE respects initial backpressure, collapses overflow, and resumes on drain", () => {
  const bus = new Broadcaster(8);
  const response = new SlowResponse();
  bus.subscribe(response as unknown as ServerResponse, null);
  for (let i = 0; i < 1024; i++) bus.publish({ value: i });
  assert.equal(response.chunks.length, 1, "no writes allowed before drain, including retry backpressure");
  assert.ok(bus.dropped > 0);
  response.slow = false;
  response.emit("drain");
  assert.ok(response.chunks.some(chunk => chunk.includes("observer backpressure")));
  bus.publish({ value: "live" });
  assert.ok(response.chunks.at(-1)?.includes("live"));
  response.end();
  bus.publish({ value: "closed" });
  assert.equal(bus.subscribers, 0);
  bus.stop();
});

test("SSE oversized frames reset instead of entering the response buffer", () => {
  const bus = new Broadcaster(1);
  const response = new SlowResponse();
  response.slow = false;
  bus.subscribe(response as unknown as ServerResponse, null);
  bus.publish({ payload: "x".repeat(2 * 1024 * 1024) });
  assert.ok(response.chunks.at(-1)?.includes("observer backpressure"));
  assert.ok(response.chunks.every(chunk => Buffer.byteLength(chunk) < 1024));
  bus.stop();
});

test("password crypto rejects work above capacity and recovers after completion", async () => {
  const attempts = Array.from({ length: PASSWORD_WORK_LIMIT + 1 }, () => hashPassword("bounded-work-password"));
  const results = await Promise.allSettled(attempts);
  assert.equal(results.filter(r => r.status === "fulfilled").length, PASSWORD_WORK_LIMIT);
  const refused = results.at(-1);
  assert.ok(refused?.status === "rejected" && refused.reason instanceof PasswordWorkBusy);
  assert.match(await hashPassword("legitimate-recovery-password"), /^scrypt\$/);
});

test("password-change attempts share a user budget across sessions and return429", async t => {
  const root = await mkdtemp(path.join(os.tmpdir(), "zeus-resource-"));
  const system = bootstrap({ dbFile: ":memory:", uploadDir: root, sessions: 0, tps: 0, env: {} });
  const server = createArbiterServer({ runtime: system.runtime, consoleOrigins: [], staticDir: null });
  t.after(async () => {
    await new Promise<void>(resolve => server.close(() => resolve()));
    system.runtime.stop(); system.store.close();
    assert.ok(root.startsWith(os.tmpdir() + path.sep));
    await rm(root, { recursive: true, force: true });
  });
  const context = { ipHash: "test", ip: "127.0.0.1", userAgent: "test" };
  const first = await system.auth.signup({ email: "limits@example.invalid", displayName: "Test", password: "Unrelated-valid-secret-917!", acceptPrivacy: true, acceptTerms: true, acceptMarketing: false }, context);
  const second = await system.auth.login("limits@example.invalid", "Unrelated-valid-secret-917!", context);
  assert.ok(first.ok && second.ok);
  await new Promise<void>(resolve => server.listen(0, "127.0.0.1", resolve));
  const url = `http://127.0.0.1:${(server.address() as AddressInfo).port}/v1/auth/password`;
  const statuses: number[] = [];
  for (let i = 0; i < 8; i++) {
    const grant = i % 2 === 0 ? first.value : second.value;
    const response = await fetch(url, { method: "POST", headers: { "content-type": "application/json", cookie: grant.cookie.split(";")[0]!, "x-zeus-csrf": grant.identity.csrf }, body: JSON.stringify({ current: "wrong", next: "Different-valid-secret-812!" }) });
    statuses.push(response.status); await response.text();
  }
  assert.deepEqual(statuses, [401, 401, 401, 429, 429, 429, 429, 429]);
});

test("upload reservations bound concurrent users and retain quota until deletion succeeds", async t => {
  const root = await mkdtemp(path.join(os.tmpdir(), "zeus-quota-"));
  let now = Date.now();
  const system = bootstrap({ dbFile: ":memory:", uploadDir: root, sessions: 0, tps: 0, env: {} });
  t.after(async () => { system.runtime.stop(); system.store.close(); assert.ok(root.startsWith(os.tmpdir() + path.sep)); await rm(root, { recursive: true, force: true }); });
  for (const userId of ["one", "two", "three"]) system.store.insertUser({ id: userId, email: `${userId}@example.invalid`, displayName: userId, role: "CUSTOMER", pwdHash: "unused", now, mustChangePassword: false });
  const files = new UploadStore(root);
  let finish!: () => void;
  const pending = new Promise<void>(resolve => { finish = resolve; });
  t.mock.method(files, "write", async () => { await pending; });
  const service = new UploadService({ store: system.store, files, now: () => now, retentionDays: 1, quotas: { userBytes: 4, userFiles: 2, globalBytes: 8, globalFiles: 3 } });
  const body = JSON.stringify({ name: "test.txt", type: "text/plain", data: Buffer.from("abcd").toString("base64"), requestRef: null });
  const one = service.intake(body, "one", "test");
  const sameUser = await service.intake(body, "one", "test");
  assert.ok(!sameUser.ok && sameUser.code === "QUOTA");
  const two = service.intake(body, "two", "test");
  const global = await service.intake(body, "three", "test");
  assert.ok(!global.ok && global.code === "QUOTA");
  finish(); assert.ok((await one).ok && (await two).ok);
  now += 2 * 24 * 60 * 60 * 1000;
  const failedRemove = t.mock.method(files, "remove", async () => false);
  assert.equal(await service.sweep(), 0);
  assert.equal(system.store.uploadUsage(null).bytes, 8);
  failedRemove.mock.restore();
  assert.equal(await service.sweep(), 2);
  assert.equal(system.store.uploadUsage(null).bytes, 0);
  assert.ok((await service.intake(body, "three", "test")).ok);
});

test("failed upload writes retain reservations when cleanup fails", async t => {
  const root = await mkdtemp(path.join(os.tmpdir(), "zeus-write-"));
  const system = bootstrap({ dbFile: ":memory:", uploadDir: root, sessions: 0, tps: 0, env: {} });
  t.after(async () => { system.runtime.stop(); system.store.close(); assert.ok(root.startsWith(os.tmpdir() + path.sep)); await rm(root, { recursive: true, force: true }); });
  system.store.insertUser({ id: "one", email: "one@example.invalid", displayName: "one", role: "CUSTOMER", pwdHash: "unused", now: Date.now(), mustChangePassword: false });
  const files = new UploadStore(root);
  t.mock.method(files, "write", async () => { throw new Error("disk failure"); });
  const remove = t.mock.method(files, "remove", async () => false);
  const service = new UploadService({ store: system.store, files, now: () => Date.now(), retentionDays: 1, quotas: { userBytes: 4, userFiles: 1, globalBytes: 4, globalFiles: 1 } });
  const body = JSON.stringify({ name: "test.txt", type: "text/plain", data: Buffer.from("abcd").toString("base64"), requestRef: null });
  assert.equal((await service.intake(body, "one", "test")).ok, false);
  assert.equal(system.store.uploadUsage(null).bytes, 4);
  assert.equal((await service.intake(body, "one", "test")).ok, false);
  remove.mock.restore();
  // Failed cleanup leaves a durable row; no orphan or freed reservation.
  assert.equal(system.store.countLiveUploads("one"), 1);
  assert.equal(system.store.uploadsForUser("one", 1)[0]?.verdict, "REJECTED");
});

test("refused upload metadata consumes file quota, and insert failure never writes bytes", async t => {
  const root = await mkdtemp(path.join(os.tmpdir(), "zeus-metadata-"));
  const system = bootstrap({ dbFile: ":memory:", uploadDir: root, sessions: 0, tps: 0, env: {} });
  t.after(async () => { system.runtime.stop(); system.store.close(); assert.ok(root.startsWith(os.tmpdir() + path.sep)); await rm(root, { recursive: true, force: true }); });
  for (const id of ["one", "two"]) system.store.insertUser({ id, email: `${id}@example.invalid`, displayName: id, role: "CUSTOMER", pwdHash: "unused", now: Date.now(), mustChangePassword: false });
  const files = new UploadStore(root);
  const writes = t.mock.method(files, "write", async () => {});
  const service = new UploadService({ store: system.store, files, now: () => Date.now(), retentionDays: 1, quotas: { userBytes: 4, userFiles: 1, globalBytes: 8, globalFiles: 2 } });
  const rejectedBody = JSON.stringify({ name: "test.txt", type: "text/plain", data: Buffer.from([0x50, 0x4b, 0x03, 0x04]).toString("base64"), requestRef: null });
  const rejected = await service.intake(rejectedBody, "one", "test");
  assert.ok(rejected.ok && rejected.verdict === "REJECTED");
  assert.deepEqual(system.store.uploadUsage("one"), { files: 1, bytes: 0 });
  const quota = await service.intake(rejectedBody, "one", "test");
  assert.ok(!quota.ok && quota.code === "QUOTA");
  t.mock.method(system.store, "insertUpload", () => { throw new Error("database failure"); });
  const validBody = JSON.stringify({ name: "test.txt", type: "text/plain", data: Buffer.from("abcd").toString("base64"), requestRef: null });
  await assert.rejects(service.intake(validBody, "two", "test"), /database failure/);
  assert.equal(writes.mock.callCount(), 0);
  assert.deepEqual(system.store.uploadUsage("two"), { files: 0, bytes: 0 });
});
