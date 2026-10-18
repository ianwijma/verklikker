import { createHash, timingSafeEqual, randomBytes } from "node:crypto";
import { spawn } from "node:child_process";
export const hash = (value: string | Uint8Array) =>
  createHash("sha256").update(value).digest("hex");
export const secret = () => randomBytes(32).toString("base64url");
export const equal = (a: string, b: string) =>
  timingSafeEqual(Buffer.from(hash(a)), Buffer.from(hash(b)));
export const sleep = (ms: number, signal?: AbortSignal) =>
  new Promise<void>((resolve, reject) => {
    if (signal?.aborted) return reject(signal.reason);
    const done = () => {
      clearTimeout(timer);
      signal?.removeEventListener("abort", abort);
    };
    const abort = () => {
      done();
      reject(signal?.reason);
    };
    const timer = setTimeout(() => {
      done();
      resolve();
    }, ms);
    signal?.addEventListener("abort", abort, { once: true });
  });
export async function command(
  bin: string,
  args: string[],
  options: { cwd?: string; signal?: AbortSignal; timeout?: number } = {},
): Promise<string> {
  return new Promise((resolve, reject) => {
    const child = spawn(bin, args, {
      cwd: options.cwd,
      signal: options.signal,
      stdio: ["ignore", "pipe", "pipe"],
      timeout: options.timeout ?? 30000,
    });
    let stdout = "",
      stderr = "";
    let overflow = false;
    const append = (s: string, data: Buffer) => {
      if (s.length + data.length > 8 * 1024 * 1024) {
        overflow = true;
        child.kill("SIGKILL");
        return s;
      }
      return s + data.toString();
    };
    child.stdout.on("data", (d) => {
      stdout = append(stdout, d);
    });
    child.stderr.on("data", (d) => {
      stderr = append(stderr, d);
    });
    child.on("error", reject);
    child.on("close", (code) =>
      code === 0 && !overflow
        ? resolve(stdout.trim())
        : reject(
            new Error(
              `${bin} failed (${code}): ${overflow ? "output limit" : stderr.slice(-4000)}`,
            ),
          ),
    );
  });
}
export function required(name: string): string {
  const v = process.env[name];
  if (!v) throw new Error(`${name} is required`);
  return v;
}
