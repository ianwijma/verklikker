import { Client } from "../packages/core/client.js";
import { required, sleep } from "../packages/core/util.js";
import { runSpec, terminalStates } from "../packages/contracts/index.js";
import { writeFile } from "node:fs/promises";
const client = new Client(
  required("VERKLIKKER_URL"),
  required("VERKLIKKER_TOKEN"),
);
const count = Number(process.env.JOBS ?? 1000),
  target = Number(process.env.TARGET_CONCURRENCY ?? 200);
if (!Number.isInteger(count) || count < 1 || count > 5000)
  throw new Error("JOBS must be 1..5000");
const ids: string[] = [];
const prefix = `capacity-${Date.now()}`;
for (let start = 0; start < count; start += 500) {
  const result = await client.request("/v1/batches", {
    jobs: Array.from({ length: Math.min(500, count - start) }, (_, i) => ({
      idempotencyKey: `${prefix}-${start + i}`,
      spec: runSpec.parse({
        label: `${prefix}-${start + i}`,
        image: "verklikker/npm:local",
        argv: [
          "node",
          "-e",
          'setTimeout(()=>console.log("capacity-probe"),60000)',
        ],
        limits: {
          timeoutSeconds: 90,
          observeSeconds: 0,
          evidenceBytes: 1024 ** 3,
        },
      }),
    })),
  });
  for (const item of result.results) {
    if (!item.run) throw new Error(item.error);
    ids.push(item.run.id);
  }
}
let peak = 0;
const states = new Map<string, string>();
let complete = false;
const deadline = Date.now() + 6 * 3600 * 1000;
try {
  while (Date.now() < deadline) {
    let active = 0,
      done = 0;
    // One database snapshot measures simultaneous running workloads, excluding boot/collection.
    const rows = await client.request("/v1/runs/status", { ids });
    for (const r of rows) {
      states.set(
        r.id,
        r.state === "completed" && r.capture_health !== "healthy"
          ? "incomplete"
          : r.state,
      );
      if (r.state === "running") active++;
      if (terminalStates.includes(r.state)) done++;
    }
    peak = Math.max(peak, active);
    console.log(JSON.stringify({ done, total: count, active, peak }));
    if (done === count) {
      complete = true;
      break;
    }
    await sleep(3000);
  }
} finally {
  await writeFile(
    "capacity-result.json",
    JSON.stringify(
      { count, target, peak, states: Object.fromEntries(states), complete },
      null,
      2,
    ),
  );
}
if (
  peak < target ||
  states.size !== count ||
  [...states.values()].some((s) => s !== "completed")
)
  throw new Error(
    "Capacity target or completion criterion was not met; inspect capacity-result.json",
  );
