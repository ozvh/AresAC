/**
 * Unity demo enrolment recipe — DEMO ONLY, loopback only.
 *
 * The production system has no external enrolment exchange (see the known limitations in
 * `README.md`): an agent's key is derived from `ZEUS_MASTER_KEY` and an enrolment counter,
 * and only the arbiter process holds it. A game client living in another process therefore
 * has no way to be provisioned — which is exactly why the real system still needs a
 * per-agent enrolment exchange that does not exist yet.
 *
 * For the demo that gap is closed with a recipe both sides can compute:
 *
 *   master = SHA256(utf8(DEMO_PASSPHRASE))                                    // 32 bytes
 *   id     = hex(HMAC_SHA256(master, "agent-id:" + role + ":" + counter))[0..16]
 *   key    = HMAC_SHA256(master, "agent-key:" + id)                           // 32 bytes
 *   sig    = hex(HMAC_SHA256(key, events.map(canonical).join("\n")))
 *
 * The demo arbiter pins `ZEUS_MASTER_KEY` to the hex of `demoMaster()`, so its own
 * `AgentRegistry.enroll()` mints exactly these ids. `tests/unity-demo.test.ts` asserts that
 * equality — that assertion is what keeps this file, `tools/unity-demo.ts` and the C# port in
 * `unity/Assets/Zeus/Scripts/ZeusWire.cs` from drifting apart.
 *
 * The passphrase below is public on purpose and is a credential to nothing. It must never be
 * used outside the loopback demo: anything derived from a published string is published.
 */
import { createHash, createHmac } from "node:crypto";
import type { Role } from "../shared/protocol.ts";

/** Public by design. Not a production secret, and not derived from one. */
export const DEMO_PASSPHRASE = "zeus-unity-demo/loopback-only-not-a-production-secret";

/**
 * Enrolment order the demo arbiter uses. The registry's counter is global and increments per
 * enrolment, so this order fixes the counters at KMOD=1, UMON=2, SRV=3.
 */
export const DEMO_ROLES: readonly Role[] = ["KMOD", "UMON", "SRV"];

/** The demo master secret: 32 bytes, derived from the public passphrase. */
export function demoMaster(): Buffer {
  return createHash("sha256").update(DEMO_PASSPHRASE, "utf8").digest();
}

/** Agent id for one (role, counter) pair, 16 lowercase hex. */
export function demoAgentId(role: Role, counter: number): string {
  return createHmac("sha256", demoMaster())
    .update(`agent-id:${role}:${counter}`, "utf8")
    .digest("hex")
    .slice(0, 16);
}

/** Per-agent MAC key, 32 bytes. Mirrors `AgentRegistry.enroll()` in `server/agents.ts`. */
export function demoAgentKey(id: string): Buffer {
  return createHmac("sha256", demoMaster()).update(`agent-key:${id}`, "utf8").digest();
}

/** The recipe's MAC. `signEvent()` in `server/agents.ts` must produce the same value. */
export function demoSign(key: Buffer, message: string): string {
  return createHmac("sha256", key).update(message, "utf8").digest("hex");
}

/**
 * The subject digest a demo player reports under. 32 lowercase hex, as the schema requires —
 * a digest, never an account identifier.
 */
export function demoSubject(name: string): string {
  return createHash("sha256").update(`zeus-unity-demo-subject:${name}`, "utf8").digest("hex").slice(0, 32);
}
