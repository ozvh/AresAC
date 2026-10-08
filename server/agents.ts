/**
 * Agent enrolment. Each reporting ring instance is a distinct principal with its
 * own HMAC key, so a compromised user-mode sentinel cannot present itself as the
 * kernel driver. Keys are derived from a master secret and never persisted.
 */
import { createHmac, randomBytes, timingSafeEqual } from "node:crypto";
import type { Role } from "../shared/protocol.ts";

export type Agent = {
  readonly id: string;
  readonly role: Role;
  readonly key: Buffer;
};

const ID_HEX = 16;

function derive(master: Buffer, label: string): Buffer {
  return createHmac("sha256", master).update(label, "utf8").digest();
}

export class AgentRegistry {
  readonly #master: Buffer;
  readonly #byId = new Map<string, Agent>();
  #counter = 0;

  constructor(master: Buffer) {
    this.#master = master;
  }

  /** Derive the master secret from the environment, or mint an ephemeral one. */
  static masterFromEnv(env: NodeJS.ProcessEnv): { master: Buffer; ephemeral: boolean } {
    const raw = env["ZEUS_MASTER_KEY"];
    if (typeof raw === "string" && /^[0-9a-f]{64}$/i.test(raw)) {
      return { master: Buffer.from(raw, "hex"), ephemeral: false };
    }
    return { master: randomBytes(32), ephemeral: true };
  }

  enroll(role: Role): Agent {
    this.#counter += 1;
    const id = derive(this.#master, `agent-id:${role}:${this.#counter}`).toString("hex").slice(0, ID_HEX);
    const key = derive(this.#master, `agent-key:${id}`);
    const agent: Agent = { id, role, key };
    this.#byId.set(id, agent);
    return agent;
  }

  get(id: string): Agent | undefined {
    return this.#byId.get(id);
  }

  get size(): number {
    return this.#byId.size;
  }

  /** Unambiguous key fingerprint for the boot banner. Never reveals key material. */
  get fingerprint(): string {
    return derive(this.#master, "fingerprint").toString("hex").slice(0, 12);
  }
}

/** Constant-time MAC verification. Length is compared first to avoid throwing. */
export function verifyMac(key: Buffer, message: string, presentedHex: string): boolean {
  if (!/^[0-9a-f]{64}$/i.test(presentedHex)) return false;
  const expected = createHmac("sha256", key).update(message, "utf8").digest();
  const presented = Buffer.from(presentedHex, "hex");
  if (presented.length !== expected.length) return false;
  return timingSafeEqual(expected, presented);
}

export function signEvent(key: Buffer, message: string): string {
  return createHmac("sha256", key).update(message, "utf8").digest("hex");
}
