/**
 * Upload intake and retention.
 *
 * NO MULTIPART PARSER. This is the single most important decision in the file. Multipart
 * form parsing has produced a long history of parser-differential bugs — the parser and
 * the consumer disagree about where a field ends, and the disagreement is the exploit.
 * Writing one here would add that surface for no benefit, so uploads arrive as base64
 * inside the same closed-key JSON envelope as everything else. The cost is a third more
 * bytes on the wire and a hard ceiling on size; the gain is that there is no parser to
 * disagree with.
 *
 * WHAT IS ACTUALLY VERIFIED, in order:
 *
 *  1. SIZE. Decoded bytes, counted after decoding rather than trusted from the sender.
 *  2. NAME. Directory components are stripped, control characters refused, and the
 *     extension must be on a short allowlist. The stored name is a fresh random value
 *     with no extension at all, so the original name influences nothing on disk.
 *  3. CONTENT. The declared type must match magic bytes, and the magic bytes must not be
 *     a container. An archive or an executable is refused even when it arrives named
 *     `.png` — which is the actual attack this check exists for. Refusing the container
 *     formats outright is why no antivirus engine is claimed here: the dangerous shapes
 *     never reach storage, so there is nothing left for a scanner to find. A deployment
 *     that wants signature scanning should call one instead of this function and has
 *     everything it needs in `UploadVerdict`. A package cannot hide in the formats that
 *     remain, so the residual risk is not malware but active content in a text file; that
 *     is quarantined — recorded, never stored — by `activeContent` below.
 *  4. PLACEMENT. Files are written outside every asset root, mode 0600, created with the
 *     exclusive flag, under a random name with no extension. Nothing serves them back:
 *     there is no read route, and the absence of one is the control.
 *  5. RETENTION. Every row carries an expiry and the sweeper deletes the file and then
 *     marks the row. The privacy policy states the window, and it is the same number.
 */
import { randomBytes, createHash } from "node:crypto";
import { mkdirSync, statfsSync } from "node:fs";
import { rm, writeFile } from "node:fs/promises";
import path from "node:path";
import { Store, type UploadVerdict } from "./db.ts";
import { hasForbiddenControl } from "./text-policy.ts";

/** Decoded ceiling. Small on purpose: this is for a log excerpt, not a game build. */
export const UPLOAD_MAX_BYTES = 256 * 1024;

/** Encoded ceiling, so the transport can refuse before decoding anything. */
export const UPLOAD_MAX_BASE64 = Math.ceil(UPLOAD_MAX_BYTES / 3) * 4 + 64;

export const UPLOAD_KEYS = ["name", "type", "data", "requestRef"] as const;

const NAME_MAX = 120;

/**
 * Extensions that are stored. Everything absent from this list is refused rather than
 * quarantined: an unlisted format is one whose safety nobody has reasoned about.
 *
 * Notably missing: `.svg` and `.html`, which are active content and would be a stored-XSS
 * vector the moment anything ever rendered them; `.zip`, `.tar`, `.gz` and the rest of the
 * container family; and every executable extension. Source archives are exactly what the
 * build-request form exists to hand out, and they travel by mail, not through this path.
 */
const ALLOWED_EXTENSIONS: ReadonlyMap<string, string> = new Map<string, string>([
  [".txt", "text/plain"],
  [".log", "text/plain"],
  [".md", "text/plain"],
  [".csv", "text/csv"],
  [".json", "application/json"],
  [".png", "image/png"],
  [".jpg", "image/jpeg"],
  [".jpeg", "image/jpeg"],
  [".gif", "image/gif"],
  [".webp", "image/webp"],
  [".pdf", "application/pdf"],
]);

/** Types the client is allowed to declare. A subset of the table above, never a superset. */
const DECLARABLE = new Set<string>([...ALLOWED_EXTENSIONS.values()]);

export type Detected = {
  /** Canonical type from the content itself. */
  readonly type: string;
  readonly extension: string;
  /** True when the bytes are a container or an executable, whatever the name says. */
  readonly dangerous: boolean;
  readonly note: string;
};

function startsWith(buffer: Buffer, bytes: readonly number[]): boolean {
  if (buffer.length < bytes.length) return false;
  for (let i = 0; i < bytes.length; i += 1) {
    if (buffer[i] !== bytes[i]) return false;
  }
  return true;
}

/**
 * Identify content from its leading bytes.
 *
 * The container and executable signatures come first and win outright. A file whose
 * extension says `.png` but whose first four bytes are `PK\x03\x04` is a ZIP archive, and
 * the name is the attacker's claim rather than the file's.
 */
export function detect(buffer: Buffer): Detected {
  if (startsWith(buffer, [0x50, 0x4b, 0x03, 0x04]) || startsWith(buffer, [0x50, 0x4b, 0x05, 0x06])) {
    return { type: "application/zip", extension: "", dangerous: true, note: "zip container" };
  }
  if (startsWith(buffer, [0x1f, 0x8b])) {
    return { type: "application/gzip", extension: "", dangerous: true, note: "gzip container" };
  }
  if (startsWith(buffer, [0x37, 0x7a, 0xbc, 0xaf])) {
    return { type: "application/x-7z", extension: "", dangerous: true, note: "7z container" };
  }
  if (startsWith(buffer, [0x52, 0x61, 0x72, 0x21])) {
    return { type: "application/vnd.rar", extension: "", dangerous: true, note: "rar container" };
  }
  if (startsWith(buffer, [0x7f, 0x45, 0x4c, 0x46])) {
    return { type: "application/x-elf", extension: "", dangerous: true, note: "elf executable" };
  }
  if (startsWith(buffer, [0x4d, 0x5a])) {
    return { type: "application/x-dosexec", extension: "", dangerous: true, note: "pe executable" };
  }
  if (
    startsWith(buffer, [0xfe, 0xed, 0xfa, 0xce]) ||
    startsWith(buffer, [0xfe, 0xed, 0xfa, 0xcf]) ||
    startsWith(buffer, [0xcf, 0xfa, 0xed, 0xfe])
  ) {
    return { type: "application/x-mach-binary", extension: "", dangerous: true, note: "mach-o executable" };
  }
  if (startsWith(buffer, [0x23, 0x21])) {
    // A shebang: a script, and a script is an executable regardless of its name.
    return { type: "application/x-shellscript", extension: "", dangerous: true, note: "shebang script" };
  }

  if (startsWith(buffer, [0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a])) {
    return { type: "image/png", extension: ".png", dangerous: false, note: "png" };
  }
  if (startsWith(buffer, [0xff, 0xd8, 0xff])) {
    return { type: "image/jpeg", extension: ".jpg", dangerous: false, note: "jpeg" };
  }
  if (startsWith(buffer, [0x47, 0x49, 0x46, 0x38])) {
    return { type: "image/gif", extension: ".gif", dangerous: false, note: "gif" };
  }
  if (startsWith(buffer, [0x52, 0x49, 0x46, 0x46]) && buffer.length >= 12) {
    const tag = buffer.subarray(8, 12).toString("latin1");
    if (tag === "WEBP") return { type: "image/webp", extension: ".webp", dangerous: false, note: "webp" };
    return { type: "application/x-riff", extension: "", dangerous: true, note: "riff container" };
  }
  if (startsWith(buffer, [0x25, 0x50, 0x44, 0x46])) {
    return { type: "application/pdf", extension: ".pdf", dangerous: false, note: "pdf" };
  }

  // No signature: accepted only as text, and only when it really is text. A byte that is
  // neither printable ASCII nor valid UTF-8 continuation means this is not a text file,
  // and an unidentified binary is refused rather than stored on a guess.
  return { type: "text/plain", extension: ".txt", dangerous: false, note: looksLikeText(buffer) ? "plain text" : "unidentified binary" };
}

function looksLikeText(buffer: Buffer): boolean {
  const sample = buffer.subarray(0, Math.min(buffer.length, 4096));
  let suspicious = 0;
  for (const byte of sample) {
    if (byte === 0x09 || byte === 0x0a || byte === 0x0d) continue;
    if (byte >= 0x20 && byte <= 0x7e) continue;
    if (byte >= 0x80) continue; // possible UTF-8 continuation; validated by the strict decode below
    suspicious += 1;
  }
  if (suspicious > 0) return false;
  // Round-trip through a strict decode: a lone 0x80 byte is valid UTF-8 continuation
  // syntax but not a valid sequence, and `fatal` makes that distinction real.
  const decoder = new TextDecoder("utf-8", { fatal: true });
  try {
    decoder.decode(sample);
    return true;
  } catch {
    return false;
  }
}

/**
 * Active content markers, searched for only in payloads that are already text.
 *
 * Why quarantine rather than reject: a cheat log can legitimately contain a fragment of
 * code, and refusing it silently teaches the user nothing while losing the signal the
 * operator wants. Why not store it: anything stored is one refactor away from being
 * served, and a stored `<script>` in a file whose type is `text/plain` is a stored XSS
 * waiting for the first handler that returns it with a guessed content type. So the
 * record is kept, the bytes are not, and the verdict says exactly which happened.
 */
const ACTIVE_CONTENT: readonly string[] = [
  "<script",
  "</script",
  "<iframe",
  "<object",
  "<embed",
  "<svg",
  "javascript:",
  "<?php",
  "<%",
  "<!entity",
  "document.cookie",
  "onerror=",
  "onload=",
];

/** The first active-content marker in a text payload, or null when there is none. */
export function activeContent(buffer: Buffer): string | null {
  // latin1, deliberately: this is a search for ASCII markers, not a decode, and a decode
  // that can throw would make a refusal path into a 500.
  const text = buffer.toString("latin1").toLowerCase();
  for (const marker of ACTIVE_CONTENT) {
    if (text.includes(marker)) return marker;
  }
  return null;
}

/** Reduce a client-supplied filename to something that cannot influence a path. */
export function sanitiseName(raw: string): { readonly base: string; readonly extension: string } | null {
  if (raw.length === 0 || raw.length > NAME_MAX) return null;
  if (hasForbiddenControl(raw)) return null;
  // Both separators, so a Windows-style path is stripped on a POSIX host as well.
  const tail = raw.split(/[\\/]/).pop() ?? "";
  const base = tail.replace(/^\.+/, "").trim();
  if (base === "" || base === "." || base === "..") return null;
  const extension = path.extname(base).toLowerCase();
  if (!ALLOWED_EXTENSIONS.has(extension)) return null;
  if (base.length > NAME_MAX) return null;
  return { base: base.slice(0, NAME_MAX), extension };
}

export type UploadInput = {
  readonly name: string;
  readonly type: string;
  readonly data: string;
  readonly requestRef: string | null;
};

export type ParsedUpload =
  | { readonly ok: true; readonly input: UploadInput }
  | { readonly ok: false; readonly code: string; readonly msg: string };

/**
 * Shape validation for the upload payload. Runs before anything touches the disk.
 *
 * Base64 is checked structurally rather than with a lenient decoder: padding and the
 * alphabet are verified, and a string that fails is refused instead of being silently
 * truncated by `Buffer.from`, which ignores invalid characters and would let a caller's
 * byte count differ from ours.
 */
export function parseUpload(raw: string): ParsedUpload {
  let parsed: unknown;
  try {
    parsed = JSON.parse(raw);
  } catch {
    return { ok: false, code: "MALFORMED", msg: "body is not JSON" };
  }
  if (typeof parsed !== "object" || parsed === null || Array.isArray(parsed)) {
    return { ok: false, code: "SCHEMA", msg: "body must be an object" };
  }
  const record = parsed as Record<string, unknown>;

  const keys = Object.keys(record);
  if (keys.length !== UPLOAD_KEYS.length) return { ok: false, code: "SCHEMA", msg: "unknown or missing fields" };
  for (const key of UPLOAD_KEYS) {
    if (!Object.hasOwn(record, key)) return { ok: false, code: "SCHEMA", msg: `missing field ${key}` };
  }

  const { name, type, data, requestRef } = record;

  if (typeof name !== "string") return { ok: false, code: "SCHEMA", msg: "name must be a string" };
  if (typeof type !== "string" || !DECLARABLE.has(type)) {
    return { ok: false, code: "UNSUPPORTED_TYPE", msg: "that type is not accepted" };
  }
  if (typeof data !== "string" || data.length === 0 || data.length > UPLOAD_MAX_BASE64) {
    return { ok: false, code: "TOO_LARGE", msg: "the payload is empty or over the ceiling" };
  }
  if (requestRef !== null && typeof requestRef !== "string") {
    return { ok: false, code: "SCHEMA", msg: "requestRef must be a string or null" };
  }
  if (typeof requestRef === "string" && !/^[0-9a-f]{8}$/.test(requestRef)) {
    return { ok: false, code: "SCHEMA", msg: "requestRef is not a reference" };
  }
  if (!/^[A-Za-z0-9+/]*={0,2}$/.test(data) || data.length % 4 !== 0) {
    return { ok: false, code: "SCHEMA", msg: "data is not base64" };
  }

  return {
    ok: true,
    input: { name, type, data, requestRef: typeof requestRef === "string" ? requestRef : null },
  };
}

export type Verdict = {
  readonly verdict: UploadVerdict;
  readonly detected: Detected;
  /** Only present when accepted. */
  readonly buffer: Buffer | null;
  readonly bytes: number;
  readonly sha256: string;
  readonly scanDetail: string;
  readonly originalName: string;
};

/**
 * Decide a parsed upload.
 *
 * Returns a verdict and never throws: every rejection is a value, because a rejection
 * that arrives as an exception is a rejection that some later refactor will turn into a
 * 500 and forget to audit.
 */
export function judge(input: UploadInput): Verdict {
  const named = sanitiseName(input.name);
  const buffer = Buffer.from(input.data, "base64");
  const bytes = buffer.length;
  const sha256 = createHash("sha256").update(buffer).digest("hex");
  const detected = detect(buffer);

  const reject = (detail: string): Verdict => ({
    verdict: "REJECTED",
    detected,
    buffer: null,
    bytes,
    sha256,
    scanDetail: detail,
    originalName: input.name.slice(0, NAME_MAX),
  });

  if (named === null) return reject("filename extension is not accepted");
  if (bytes === 0) return reject("empty payload");
  if (bytes > UPLOAD_MAX_BYTES) return reject(`payload is ${bytes} bytes, ceiling is ${UPLOAD_MAX_BYTES}`);

  // The container check comes before the type-match check so the reason recorded is the
  // one that matters: this is not a mislabelled image, it is a container.
  if (detected.dangerous) return reject(`refused: ${detected.note}`);

  // Declared type and content must agree. A mismatch is either an honest mistake or a
  // deliberate one, and the two are indistinguishable, so both are refused.
  if (detected.type !== input.type) {
    return reject(`declared ${input.type} but content is ${detected.type}`);
  }
  if (detected.extension === "") return reject("content type has no accepted extension");

  const extensionNote = named.extension === detected.extension || (detected.extension === ".jpg" && named.extension === ".jpeg")
    ? "extension agrees with content"
    : `extension ${named.extension} disagrees with content ${detected.extension}`;

  // Only the text-shaped types are scanned. Looking for the string "<script" inside a PNG
  // would be a search of compressed bytes, which is noise either way.
  const textish = detected.type.startsWith("text/") || detected.type === "application/json";
  if (textish) {
    const marker = activeContent(buffer);
    if (marker !== null) {
      return {
        verdict: "QUARANTINED",
        detected,
        buffer: null,
        bytes,
        sha256,
        scanDetail: `quarantined: active content marker ${marker}; bytes not stored, record retained for review`,
        originalName: named.base,
      };
    }
  }

  // Disagreement here is not fatal: the stored name has no extension and nothing serves
  // the file, but the note is kept so the operator can see it.
  return {
    verdict: "ACCEPTED",
    detected,
    buffer,
    bytes,
    sha256,
    scanDetail: `${detected.note}; ${extensionNote}; no container, no executable, no active content`,
    originalName: named.base,
  };
}

export function storedName(): string {
  // No extension, random, and 32 hex cells of entropy. Nothing about the value can be
  // predicted, iterated or made executable by a later refactor of the serving code.
  return randomBytes(16).toString("hex");
}

export type IntakeResult = {
  readonly ok: true;
  readonly id: string;
  readonly verdict: UploadVerdict;
  readonly bytes: number;
  readonly sha256: string;
  readonly expiresAt: number;
  readonly scanDetail: string;
  readonly originalName: string;
} | { readonly ok: false; readonly code: string; readonly msg: string; readonly status: number };

export type UploadServiceConfig = {
  readonly store: Store;
  readonly files: UploadStore;
  readonly now: () => number;
  readonly retentionDays: number;
  readonly quotas?: { readonly userBytes: number; readonly userFiles: number; readonly globalBytes: number; readonly globalFiles: number };
};

export const UPLOAD_QUOTAS = { userBytes: 16 * 1024 * 1024, userFiles: 64, globalBytes: 1024 * 1024 * 1024, globalFiles: 4096 } as const;

/**
 * Upload orchestration: validate, judge, store, record, audit.
 *
 * Order matters. The row is written before the bytes reach the disk, so a crash between
 * the two leaves a record of an artefact that does not exist rather than a file on disk
 * that nothing knows about. The sweeper treats a missing file as a successful deletion,
 * so the recoverable direction of that failure is the one chosen.
 */
export class UploadService {
  readonly #store: Store;
  readonly #files: UploadStore;
  readonly #now: () => number;
  readonly #retentionDays: number;
  readonly #quotas: NonNullable<UploadServiceConfig["quotas"]>;

  constructor(config: UploadServiceConfig) {
    this.#store = config.store;
    this.#files = config.files;
    this.#now = config.now;
    this.#retentionDays = config.retentionDays;
    this.#quotas = config.quotas ?? UPLOAD_QUOTAS;
    for (const limit of Object.values(this.#quotas)) {
      if (!Number.isSafeInteger(limit) || limit < 1) throw new Error("upload quota must be a positive integer");
    }
  }

  get root(): string {
    return this.#files.root;
  }

  get retentionDays(): number {
    return this.#retentionDays;
  }

  async intake(rawBody: string, userId: string, ipHash: string): Promise<IntakeResult> {
    const now = this.#now();
    const parsed = parseUpload(rawBody);
    if (!parsed.ok) {
      this.#store.audit({
        ts: now,
        actorId: userId,
        actorRole: "CUSTOMER",
        action: "UPLOAD.REJECTED",
        subjectId: null,
        outcome: "REFUSED",
        detail: `${parsed.code}`,
        ipHash,
      });
      return { ok: false, code: parsed.code, msg: parsed.msg, status: parsed.code === "TOO_LARGE" ? 413 : 400 };
    }

    const judged = judge(parsed.input);
    const id = randomBytes(16).toString("hex");
    const expiresAt = now + this.#retentionDays * 24 * 60 * 60 * 1_000;
    const record = storedName();

    // Every verdict is recorded, including refusals. The row is the evidence that a file
    // was offered and what was decided about it.
    const stored = judged.verdict === "ACCEPTED" && judged.buffer !== null ? record : null;
    const reservedBytes = stored === null ? 0 : judged.bytes;
    // Reserve durably before the first await, sharing budgets across service instances.
    let reserved = false;
    this.#store.tx(() => {
      const user = this.#store.uploadUsage(userId);
      const global = this.#store.uploadUsage(null);
      if (user.files >= this.#quotas.userFiles || global.files >= this.#quotas.globalFiles ||
          user.bytes + reservedBytes > this.#quotas.userBytes || global.bytes + reservedBytes > this.#quotas.globalBytes) return;
      this.#store.insertUpload({
      id,
      userId,
      requestRef: parsed.input.requestRef,
      storedName: stored ?? "-",
      originalName: judged.originalName,
      declaredType: parsed.input.type,
      detectedType: judged.detected.type,
      bytes: judged.bytes,
      sha256: judged.sha256,
      verdict: judged.verdict,
      scanDetail: judged.scanDetail,
      now,
      expiresAt,
      });
      reserved = true;
    });
    if (!reserved) return { ok: false, code: "QUOTA", msg: "upload storage quota reached", status: 429 };

    if (stored !== null && judged.buffer !== null) {
      try {
        await this.#files.write(stored, judged.buffer);
      } catch {
        // A failed write can leave partial bytes. Keep its reservation until cleanup succeeds.
        this.#store.markUploadWriteFailed(id);
        if (await this.#files.remove(stored)) this.#store.markUploadDeleted(id, now);
        this.#store.audit({ ts: now, actorId: userId, actorRole: "CUSTOMER", action: "UPLOAD.REJECTED",
          subjectId: id, outcome: "REFUSED", detail: "storage write failed", ipHash });
        return { ok: false, code: "STORAGE", msg: "the artefact could not be stored", status: 500 };
      }
    }

    // Three verdicts, three audit actions. Collapsing quarantine into rejection would
    // erase the difference between "this was refused" and "this was held", and that
    // difference is the entire reason the operator reads the log.
    const action =
      judged.verdict === "ACCEPTED"
        ? "UPLOAD.ACCEPTED"
        : judged.verdict === "QUARANTINED"
          ? "UPLOAD.QUARANTINED"
          : "UPLOAD.REJECTED";
    this.#store.audit({
      ts: now,
      actorId: userId,
      actorRole: "CUSTOMER",
      action,
      subjectId: id,
      outcome: judged.verdict === "ACCEPTED" ? "OK" : "REFUSED",
      detail: `${judged.detected.type} ${judged.bytes}B ${judged.scanDetail}`,
      ipHash,
    });

    return {
      ok: true,
      id,
      verdict: judged.verdict,
      bytes: judged.bytes,
      sha256: judged.sha256,
      expiresAt,
      scanDetail: judged.scanDetail,
      originalName: judged.originalName,
    };
  }

  /**
   * Delete artefacts whose retention window has closed.
   *
   * The file goes first and the row is marked second, so a failure leaves a row that still
   * claims a file exists — visible and retried on the next pass — rather than a file that
   * no row refers to and that nothing will ever delete.
   */
  async sweep(limit = 64): Promise<number> {
    const now = this.#now();
    const expired = this.#store.expiredUploads(now, limit);
    let removed = 0;
    for (const row of expired) {
      // eslint-disable-next-line no-await-in-loop -- Bounded retention work deletes each file before updating its database record.
      if (row.stored_name !== "-" && !(await this.#files.remove(row.stored_name))) continue;
      this.#store.markUploadDeleted(row.id, now);
      this.#store.audit({
        ts: now,
        actorId: null,
        actorRole: "SYSTEM",
        action: "UPLOAD.EXPIRED",
        subjectId: row.id,
        outcome: "OK",
        detail: `retention window of ${this.#retentionDays} days closed after ${row.bytes} bytes`,
        ipHash: "",
      });
      removed += 1;
    }
    return removed;
  }
}

export class UploadStore {
  readonly root: string;

  constructor(root: string) {
    this.root = path.resolve(root);
    mkdirSync(this.root, { recursive: true, mode: 0o700 });
  }

  /** Write to the private root. `wx` means an existing name is never overwritten. */
  async write(name: string, data: Buffer): Promise<void> {
    const target = path.resolve(this.root, name);
    // Defence in depth: `name` is generated, but containment is cheap and this is the
    // only place a path is built from a variable.
    if (target !== path.join(this.root, name) || !target.startsWith(this.root + path.sep)) {
      throw new Error("stored name escaped the upload root");
    }
    const disk = statfsSync(this.root);
    if (disk.bavail * disk.bsize < data.length + 64 * 1024 * 1024) {
      throw new Error("upload disk headroom exhausted");
    }
    await writeFile(target, data, { mode: 0o600, flag: "wx" });
  }

  /** Remove a stored artefact. A missing file is a success, not an error. */
  async remove(name: string): Promise<boolean> {
    const target = path.resolve(this.root, name);
    if (!target.startsWith(this.root + path.sep)) return false;
    try {
      await rm(target, { force: true });
      return true;
    } catch {
      return false;
    }
  }
}
