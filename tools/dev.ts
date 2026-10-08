/**
 * Development runner: the arbiter and the console together, one Ctrl-C to stop both.
 *
 * The console is a separate origin from the arbiter in development, so Vite proxies
 * /v1 to the arbiter process. Both are bound to loopback; nothing here is reachable
 * from another host.
 */
import { spawn, type ChildProcess } from "node:child_process";

const PORT = process.env["ARES_PORT"] ?? "8787";

function launch(label: string, command: string, args: readonly string[]): ChildProcess {
  const child = spawn(command, [...args], {
    stdio: ["ignore", "inherit", "inherit"],
    shell: process.platform === "win32",
  });
  child.on("exit", (code, signal) => {
    process.stdout.write(`[dev] ${label} exited (code ${String(code)}, signal ${String(signal)})\n`);
  });
  return child;
}

const arbiter = launch("arbiter", "node", [
  "--experimental-strip-types",
  "--no-warnings",
  "server/index.ts",
  `--port=${PORT}`,
]);

const console_ = launch("console", "npx", ["vite", "--host", "127.0.0.1", "--port", "5173"]);

let stopping = false;
const shutdown = (): void => {
  if (stopping) return;
  stopping = true;
  process.stdout.write("\n[dev] stopping\n");
  for (const child of [arbiter, console_]) {
    if (child.pid === undefined) continue;
    if (process.platform === "win32") child.kill();
    else child.kill("SIGTERM");
  }
  setTimeout(() => process.exit(0), 400);
};

process.on("SIGINT", shutdown);
process.on("SIGTERM", shutdown);
