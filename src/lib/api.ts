/**
 * Control-plane client.
 *
 * The console is a read-only observer by default. Everything here is a deliberate
 * operator action, and every one of them is refused by the arbiter unless the
 * operator token is presented.
 *
 * THE TOKEN LIVES IN MEMORY AND NOWHERE ELSE. It used to be mirrored into
 * `sessionStorage` so a reload would not ask for it again. That is a client-held
 * credential: any script running on this origin — including one injected by a
 * dependency, a browser extension, or a future XSS in a page that shares the origin —
 * can read it out of storage, and it survives as a value at rest after the tab is
 * closed and reopened. The cost of removing it is that an operator pastes the token
 * again after a reload, and the console says so where the field is. The cost of
 * keeping it is a credential that outlives the operator's attention.
 */
import type { ControlAction, ControlResult, SnapshotResponse } from "@shared/protocol";

/** In-memory only. Deliberately not a storage key: there is no such key any more. */
let token = "";

export function operatorToken(): string {
  return token;
}

export function setOperatorToken(next: string): void {
  token = next.trim();
}

export function hasOperatorToken(): boolean {
  return token.length > 0;
}

export async function fetchSnapshot(signal?: AbortSignal): Promise<SnapshotResponse | null> {
  try {
    const res = await fetch("/v1/snapshot", {
      // Spread rather than assign: with exactOptionalPropertyTypes a present-but-undefined
      // signal is not assignable to RequestInit.signal.
      ...(signal === undefined ? {} : { signal }),
      headers: { accept: "application/json" },
    });
    if (!res.ok) return null;
    return (await res.json()) as SnapshotResponse;
  } catch {
    return null;
  }
}

export type ControlOutcome = { ok: true; applied: string } | { ok: false; reason: string };

export async function sendControl(action: ControlAction): Promise<ControlOutcome> {
  if (!hasOperatorToken()) return { ok: false, reason: "operator token required" };
  try {
    const res = await fetch("/v1/control", {
      method: "POST",
      headers: {
        "content-type": "application/json",
        "x-zeus-op": token,
      },
      body: JSON.stringify(action),
    });
    const body = (await res.json()) as ControlResult | { e: string; msg: string };
    if (res.ok && "ok" in body && body.ok) return { ok: true, applied: body.applied };
    if ("msg" in body) return { ok: false, reason: `${body.e}: ${body.msg}` };
    return { ok: false, reason: `HTTP ${res.status}` };
  } catch {
    return { ok: false, reason: "transport failure" };
  }
}
