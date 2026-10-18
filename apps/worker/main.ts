import { mkdir, rm } from "node:fs/promises";
import { workerCapacity } from "../../packages/contracts/index.js";
import { arch, hostname } from "node:os";
import { join, resolve } from "node:path";
import { lookup } from "node:dns/promises";
import { randomUUID } from "node:crypto";
import { Client } from "../../packages/core/client.js";
import { doctor, run } from "../../packages/core/runner.js";
import { required, sleep, hash } from "../../packages/core/util.js";
await mkdir(process.env.TMPDIR ?? "/tmp", { recursive: true });
const client = new Client(required("API_URL"), required("WORKER_TOKEN"));
const runtime = await doctor(
  resolve(process.env.RUNTIME_DIRECTORY ?? "runtime"),
);
const capacity = workerCapacity.parse({
  cpus: Number(process.env.WORKER_CPUS ?? 2),
  memoryMiB: Number(process.env.WORKER_MEMORY_MIB ?? 4096),
  diskBytes: Number(process.env.WORKER_DISK_BYTES ?? 20 * 1024 ** 3),
  evidenceBytes: Number(process.env.WORKER_EVIDENCE_BYTES ?? 10 * 1024 ** 3),
});
const workerId = `${hostname()}-${randomUUID()}`;
let shuttingDown = false;
let current: AbortController | undefined;
process.on("SIGTERM", () => {
  shuttingDown = true;
  current?.abort();
});
process.on("SIGINT", () => {
  shuttingDown = true;
  current?.abort();
});
const protectedHosts = [
  process.env.API_URL,
  process.env.S3_ENDPOINT,
  process.env.S3_PUBLIC_ENDPOINT,
]
  .filter(Boolean)
  .map((url) => new URL(url!).hostname);
while (!shuttingDown) {
  const { run: job } = await client.request("/internal/claim", {
    workerId,
    architecture: arch(),
    capacity,
  });
  if (!job) {
    if (process.env.WORKER_ONCE === "1") break;
    await sleep(2000);
    continue;
  }
  current = new AbortController();
  const controller = current;
  let stage: "booting" | "running" | "collecting" = "booting",
    leaseUntil = Date.now() + 25000,
    busy = false;
  const prefix = `/internal/runs/${job.id}`,
    leaseToken = job.leaseToken;
  const heartbeat = setInterval(async () => {
    if (Date.now() > leaseUntil) {
      controller.abort(new Error("Worker lease expired"));
      return;
    }
    if (busy) return;
    busy = true;
    try {
      const result = await client.request(prefix + "/heartbeat", {
        leaseToken,
        state: stage,
      });
      leaseUntil = Date.now() + 25000;
      if (result.cancel) controller.abort();
    } catch (e) {
      console.error(String(e));
    } finally {
      busy = false;
    }
  }, 3000);
  try {
    const protectedIPs: string[] = [];
    for (const host of protectedHosts)
      for (const entry of await lookup(host, { all: true }))
        protectedIPs.push(entry.address);
    const result = await run(job.spec, {
      runtime,
      runId: job.id,
      attemptId: job.attempt_id,
      directory: join(process.env.EVIDENCE_DIRECTORY ?? "artifacts", job.id),
      signal: controller.signal,
      protectedIPs,
      protectedHosts,
      status: (s) => {
        stage = s;
      },
      publish: (a, path) => client.publish(job.id, leaseToken, a, path),
      input: async (id) => {
        const { url, sha256 } = await client.request(`${prefix}/inputs/${id}`, {
          leaseToken,
        });
        const res = await fetch(url, { signal: AbortSignal.timeout(30000) });
        if (!res.ok) throw new Error("Input download failed");
        const data = Buffer.from(await res.arrayBuffer());
        if (hash(data) !== sha256) throw new Error("Input checksum mismatch");
        return data;
      },
    });
    await client.request(prefix + "/finish", { leaseToken, manifest: result });
    if (process.env.KEEP_LOCAL_EVIDENCE !== "1")
      await rm(join(process.env.EVIDENCE_DIRECTORY ?? "artifacts", job.id), {
        recursive: true,
        force: true,
      });
  } catch (e) {
    console.error(`Run ${job.id}: ${String(e)}`);
    try {
      await client.request(prefix + "/finish", {
        leaseToken,
        manifest: {
          version: 1,
          runId: job.id,
          attemptId: job.attempt_id,
          state: "failed",
          captureHealth: "incomplete",
          exitCode: null,
          reason: String(e),
        },
      });
    } catch (report) {
      console.error(`Result not accepted: ${String(report)}`);
    }
  } finally {
    clearInterval(heartbeat);
    current = undefined;
  }
  if (process.env.WORKER_ONCE === "1") break;
}
