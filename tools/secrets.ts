/**
 * Secret hygiene.
 *
 * A secret in the working tree is a secret in every clone, every fork, every archive and
 * every editor's search index — and the commit that removes it does not remove it from
 * history. This tool exists because the cheapest place to catch one is before it is
 * written down, so it is deliberately blunt about the six shapes that have no business in
 * source: a working `.env`, a private key file, a provider-shaped credential, a long
 * literal assigned to a secret-shaped name, an environment value printed to output, and a
 * token handed to browser storage.
 *
 * It reads text files, contacts nothing, and has no dependencies. A clean run is expected
 * on this repository; a dirty run exits non-zero so a build can be gated on it. The tool
 * is also one of its own subjects — it scans itself, which is why no rule below spells out
 * a literal that it would flag, including the allowance marker, which is assembled rather
 * than quoted.
 *
 * An individual line of code may opt out with an inline allowance: the marker built below,
 * a colon, and a short reason. An allowance with no reason is itself a finding, because an
 * unexplained exception is how a scanner becomes decoration. The mechanism belongs to code
 * files only — a document that describes it is not claiming an exception with it.
 *
 * Run:  npm run security:secrets
 */
import { readdirSync, readFileSync, type Dirent } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");

/** Directories that are generated, third-party, or hold runtime data rather than source. */
const SKIP_DIRS: readonly string[] = ["node_modules", "dist", "coverage", "quarantine", "uploads"];
const SKIP_FILES: readonly string[] = ["package-lock.json"];
/** Extensions that are never source: logs, databases, journals. */
const SKIP_EXT: readonly string[] = [".log", ".db", ".sqlite", ".sqlite3", ".db-wal", ".db-shm"];
/** Extensions worth reading. Anything else is left alone rather than decoded as text. */
const TEXT_EXT: readonly string[] = [
  ".ts",
  ".tsx",
  ".mts",
  ".cts",
  ".js",
  ".mjs",
  ".cjs",
  ".jsx",
  ".json",
  ".md",
  ".html",
  ".css",
  ".yml",
  ".yaml",
  ".txt",
  ".example",
  ".env",
  ".sh",
  ".ps1",
  ".toml",
  ".cfg",
  ".ini",
];

const ENV_FILE = /^\.env(?:\.|$)/;
const ENV_TEMPLATE = ".env.example";
const KEY_EXT: readonly string[] = [".pem", ".key", ".p12", ".pfx", ".jks"];

/** The allowance marker, assembled so this file does not trip its own rule. */
const ALLOW = "ares-secrets" + ":allow";
const ALLOW_TAIL: RegExp = /^\s*:\s*(\S.*)$/;
const CODE_EXT = /\.(ts|tsx|mts|cts|js|mjs|cjs|jsx|sh|ps1)$/;

/**
 * Names that carry credentials. `key` on its own is deliberately absent: `sessionKey`,
 * `keyId` and `primaryKey` are ordinary identifiers here, and a rule that flags them would
 * be turned off within a week. Provider prefixes below catch the keys that matter by shape.
 */
const SECRET_NAME =
  /(api[_-]?key|apikey|secret|token|passwd|password|credential|private[_-]?key)[A-Za-z0-9_]*\s*[:=]\s*(["'`])([^"'`\n]+)\2/gi;

/** One token, no whitespace. Prose is not a credential; a base64 or hex run might be. */
const SINGLE_TOKEN = /^[A-Za-z0-9+/_\-=.:]+$/;
const LITERAL_FLOOR = 16;

/** Values that exist precisely to be recognised as not-real. */
const PLACEHOLDERS: readonly string[] = [
  "your-",
  "your_",
  "yourapi",
  "example",
  "placeholder",
  "changeme",
  "replace",
  "redacted",
  "dummy",
  "fake",
  "test-key",
  "test_key",
  "testkey",
  "xxxx",
  "abc123",
  "<",
  "process.env",
];

const PROVIDERS: ReadonlyArray<{ readonly label: string; readonly shape: RegExp }> = [
  { label: "an AWS access key id", shape: /AKIA[0-9A-Z]{16}/ },
  { label: "a GitHub token", shape: /(ghp|gho|ghs|ghr)_[A-Za-z0-9]{20,}|github_pat_[A-Za-z0-9_]{20,}/ },
  { label: "an OpenAI-style key", shape: /sk-[A-Za-z0-9]{20,}/ },
  { label: "a Stripe secret key", shape: /(sk|rk)_(live|test)_[A-Za-z0-9]{16,}/ },
  { label: "a Google API key", shape: /AIza[0-9A-Za-z_\-]{35}/ },
  { label: "a Slack token", shape: /xox[baprs]-[A-Za-z0-9-]{10,}/ },
];

/** A PEM banner. Written so the pattern text does not match itself. */
const KEY_BANNER = /-----BEGIN[A-Z ]+PRIVATE KEY-----/;

const OUTPUT_CALL =
  /(?:^|[^A-Za-z0-9_.])(console\.(?:log|error|warn|info|debug)|process\.(?:stdout|stderr)\.write)\s*\(/;
const ENV_READ = /process\.env(?:\[[^\]]*\]|\.[A-Za-z0-9_]+)/g;
/** A reference used only to ask whether it is set is not the value being printed. */
const PRESENCE_TEST = /^\s*(?:===|!==|==|!=|\?|&&|\|\||\.length\b)/;
/** Naming a variable as an assignment target is not printing its value either. */
const ENV_WRITE = /^\s*=(?!=)/;
/**
 * A write to browser storage, not a read and not a mention in prose. `getItem` and
 * `removeItem` are deliberately ignored: reading a key back and deleting it are not how a
 * credential becomes recoverable by the next script on the origin.
 */
const BROWSER_WRITE = /(?:localStorage|sessionStorage)[^\n]*?(?:\.setItem\s*\(|\[[^\]]*\]\s*=)/;
/** `TOKEN_KEY` counts; `sessionStorage` does not, hence the explicit boundary. */
const TOKENISH = /\b(csrf|token|jwt|bearer|pwd|password|secret|credential|session)(?:_|\b)/i;
const DANGEROUS_BUFFER = /Buffer\.from\s*\(/;

type Finding = { readonly where: string; readonly line: number; readonly reason: string };
type Group = { readonly label: string; readonly detail: string; readonly findings: readonly Finding[] };

function where(file: string, line: number): string {
  return line > 0 ? `${file}:${line}` : file;
}

function toRelative(absolute: string): string {
  return path.relative(ROOT, absolute).split(path.sep).join("/");
}

function walk(dir: string, out: string[]): void {
  let entries: Dirent[];
  try {
    entries = readdirSync(dir, { withFileTypes: true });
  } catch {
    return;
  }
  for (const entry of entries) {
    // Symlinks are skipped rather than followed: following one is how a scanner wanders
    // out of the tree it was asked to read.
    if (entry.isSymbolicLink()) continue;
    const full = path.join(dir, entry.name);
    if (entry.isDirectory()) {
      if (entry.name.startsWith(".") || SKIP_DIRS.includes(entry.name)) continue;
      walk(full, out);
    } else if (entry.isFile()) {
      out.push(full);
    }
  }
}

function isEnvFile(base: string): boolean {
  return ENV_FILE.test(base) && base !== ENV_TEMPLATE;
}

function isKeyFile(base: string): boolean {
  const ext = path.extname(base).toLowerCase();
  return KEY_EXT.includes(ext) || base === "id_rsa" || base.startsWith("id_rsa.");
}

function isScannable(absolute: string): boolean {
  const base = path.basename(absolute);
  if (SKIP_FILES.includes(base)) return false;
  const ext = path.extname(base).toLowerCase();
  if (SKIP_EXT.includes(ext)) return false;
  return TEXT_EXT.includes(ext);
}

/**
 * The allowance marker on a line of code: null when absent, "" when present but unexplained.
 * Prose and data files are never allowed to carry an allowance, so a policy document that
 * quotes the marker is read normally instead of silencing the rule it is describing.
 */
function allowance(rel: string, line: string): string | null {
  if (!CODE_EXT.test(rel)) return null;
  const at = line.indexOf(ALLOW);
  if (at < 0) return null;
  const tail = ALLOW_TAIL.exec(line.slice(at + ALLOW.length));
  if (tail === null) return "";
  const reason = tail[1];
  return reason === undefined ? "" : reason.trim();
}

/**
 * Line numbers occupied by a single output call. Parens are counted from the call's own
 * opening paren, so a template array spanning thirty lines is one region rather than
 * thirty unrelated ones — which is the difference between catching a printed secret and
 * missing it because the call was formatted for readability.
 */
function outputRegions(lines: readonly string[]): ReadonlySet<number> {
  const region = new Set<number>();
  lines.forEach((line, index) => {
    if (!OUTPUT_CALL.test(line)) return;
    let depth = 0;
    let opened = false;
    for (let cursor = index; cursor < lines.length && cursor < index + 400; cursor += 1) {
      for (const character of lines[cursor] ?? "") {
        if (character === "(") {
          depth += 1;
          opened = true;
        } else if (character === ")") {
          depth -= 1;
        }
      }
      region.add(cursor);
      if (opened && depth <= 0) return;
    }
  });
  return region;
}

/** A printed environment value, unless the reference is only being tested for presence. */
function printedEnvironmentValue(line: string): string | null {
  ENV_READ.lastIndex = 0;
  let match = ENV_READ.exec(line);
  while (match !== null) {
    const reference = match[0];
    const after = line.slice(match.index + reference.length);
    const before = line.slice(0, match.index).trimEnd();
    const tested = PRESENCE_TEST.test(after) || ENV_WRITE.test(after) || before.endsWith("typeof");
    if (!tested) return reference;
    match = ENV_READ.exec(line);
  }
  return null;
}

type TextFile = { readonly rel: string; readonly lines: readonly string[] };

const files: string[] = [];
walk(ROOT, files);
files.sort();

const examined = files.map((absolute) => ({ absolute, rel: toRelative(absolute) }));
const envFiles = examined.filter((file) => isEnvFile(path.basename(file.rel)));
const keyFiles = examined.filter((file) => isKeyFile(path.basename(file.rel)));

const text: TextFile[] = [];
for (const file of examined) {
  if (!isScannable(file.absolute)) continue;
  try {
    text.push({ rel: file.rel, lines: readFileSync(file.absolute, "utf8").split(/\r?\n/) });
  } catch {
    // A file that cannot be read is not evidence of a secret, and failing the scan on a
    // permissions problem would train the reader to ignore the scan.
  }
}

const groups: Group[] = [];

groups.push({
  label: "env file",
  detail: `no working .env in the tree (${ENV_TEMPLATE} is the template and holds no value)`,
  findings: envFiles.map((file) => ({
    where: where(file.rel, 0),
    line: 0,
    reason: "a working environment file is in the tree; configuration belongs in the environment",
  })),
});

groups.push({
  label: "key material",
  detail: "no private key files (*.pem, *.key, *.p12, *.pfx, id_rsa)",
  findings: keyFiles.map((file) => ({
    where: where(file.rel, 0),
    line: 0,
    reason: "a private key file is in the tree; keys belong in a secret store, never in a checkout",
  })),
});

const providerFindings: Finding[] = [];
for (const file of text) {
  file.lines.forEach((line, index) => {
    if (allowance(file.rel, line) !== null) return;
    for (const provider of PROVIDERS) {
      if (provider.shape.test(line)) {
        providerFindings.push({
          where: where(file.rel, index + 1),
          line: index + 1,
          reason: `a literal that looks like ${provider.label}`,
        });
      }
    }
    if (KEY_BANNER.test(line)) {
      providerFindings.push({
        where: where(file.rel, index + 1),
        line: index + 1,
        reason: "an embedded private key block",
      });
    }
  });
}
groups.push({
  label: "provider keys",
  detail: "no provider-shaped credentials (AWS, GitHub, OpenAI, Stripe, Google, Slack, PEM)",
  findings: providerFindings,
});

const literalFindings: Finding[] = [];
for (const file of text) {
  file.lines.forEach((line, index) => {
    if (allowance(file.rel, line) !== null) return;
    SECRET_NAME.lastIndex = 0;
    let match = SECRET_NAME.exec(line);
    while (match !== null) {
      const name = match[1] ?? "a secret-shaped name";
      const value = match[3] ?? "";
      const lower = value.toLowerCase();
      const repeated = value.length > 0 && value.split("").every((character) => character === value[0]);
      const explained =
        PLACEHOLDERS.some((placeholder) => lower.includes(placeholder)) ||
        repeated ||
        !SINGLE_TOKEN.test(value);
      if (!explained && value.length >= LITERAL_FLOOR && !value.includes("${")) {
        literalFindings.push({
          where: where(file.rel, index + 1),
          line: index + 1,
          reason: `a ${value.length}-character literal assigned to \`${name}\``,
        });
      }
      match = SECRET_NAME.exec(line);
    }
    if (DANGEROUS_BUFFER.test(line)) {
      const named = /(api[_-]?key|apikey|secret|token|passwd|password|credential)[A-Za-z0-9_]*\s*[:=]\s*/i;
      if (named.test(line) && !line.includes("process.env")) {
        literalFindings.push({
          where: where(file.rel, index + 1),
          line: index + 1,
          reason: "a credential-shaped name assigned raw bytes in source",
        });
      }
    }
  });
}
groups.push({
  label: "literals",
  detail: `no secret-shaped literal in ${text.length} files`,
  findings: literalFindings,
});

const logFindings: Finding[] = [];
for (const file of text) {
  const region = outputRegions(file.lines);
  file.lines.forEach((line, index) => {
    if (!region.has(index)) return;
    if (allowance(file.rel, line) !== null) return;
    const printed = printedEnvironmentValue(line);
    if (printed === null) return;
    logFindings.push({
      where: where(file.rel, index + 1),
      line: index + 1,
      reason: `${printed} is printed; a value read from the environment must not reach the log`,
    });
  });
}
groups.push({
  label: "logging",
  detail: "no environment value written to output (presence tests excluded)",
  findings: logFindings,
});

const storeFindings: Finding[] = [];
for (const file of text) {
  if (!file.rel.startsWith("src/")) continue;
  file.lines.forEach((line, index) => {
    if (allowance(file.rel, line) !== null) return;
    if (BROWSER_WRITE.test(line) && TOKENISH.test(line)) {
      storeFindings.push({
        where: where(file.rel, index + 1),
        line: index + 1,
        reason: "a token-shaped value reaching browser storage, where any injected script reads it",
      });
    }
  });
}
groups.push({
  label: "browser store",
  detail: "no token written to localStorage or sessionStorage under src/",
  findings: storeFindings,
});

const bareAllowances: Finding[] = [];
for (const file of text) {
  file.lines.forEach((line, index) => {
    const reason = allowance(file.rel, line);
    if (reason === "") {
      bareAllowances.push({
        where: where(file.rel, index + 1),
        line: index + 1,
        reason: "an allowance with no reason; state why the line is safe or remove it",
      });
    }
  });
}
groups.push({
  label: "allowances",
  detail: "every inline allowance carries a reason",
  findings: bareAllowances,
});

const output: string[] = [" ARES secret hygiene — text only, no network, no dependencies", ""];
let total = 0;
for (const group of groups) {
  total += group.findings.length;
  if (group.findings.length === 0) {
    output.push(`+ ${group.label.padEnd(14)} ${group.detail}`);
    continue;
  }
  for (const finding of group.findings) {
    output.push(`[x] ${group.label.padEnd(14)} ${finding.where}  ${finding.reason}`);
  }
}
output.push("");
output.push(`SCAN ${text.length} files  findings ${total}  seal ${total === 0 ? "CLEAN" : "FAIL"}`);
process.stdout.write(`${output.join("\n")}\n`);

process.exitCode = total === 0 ? 0 : 1;
