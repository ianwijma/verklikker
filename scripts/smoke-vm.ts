import assert from "node:assert/strict";
import { readFile, mkdtemp, mkdir } from "node:fs/promises";
import { join, resolve } from "node:path";
import YAML from "yaml";
import { runSpec } from "../packages/contracts/index.js";
import { doctor, run } from "../packages/core/runner.js";

const runtime = await doctor(); // Deliberately fails, rather than skips, when virtualization is missing.
const spec = runSpec.parse(
  YAML.parse(await readFile("examples/observe.yaml", "utf8")),
);
await mkdir("artifacts", { recursive: true });
const directory = await mkdtemp(resolve("artifacts") + "/smoke-");
const manifest = await run(spec, { runtime, directory });
assert.equal(manifest.state, "completed", manifest.reason);
assert.equal(manifest.captureHealth, "healthy", manifest.reason);
const records = [];
for (const a of manifest.artifacts.filter((a) => a.kind === "events"))
  records.push(
    ...(await readFile(join(directory, a.id), "utf8"))
      .trim()
      .split("\n")
      .map((l) => JSON.parse(l)),
  );
assert.ok(
  records.some((e) => /exec/.test(e.kind)),
  "process execution evidence missing",
);
assert.ok(
  records.some((e) => /write/.test(e.kind)),
  "file write evidence missing",
);
assert.ok(
  records.some((e) => /read/.test(e.kind)),
  "file read evidence missing",
);
for (const kind of ["packets", "filesystem", "raw", "index"])
  assert.ok(
    manifest.artifacts.some((a) => a.kind === kind),
    `${kind} missing`,
  );
console.log(
  JSON.stringify(
    {
      directory,
      state: manifest.state,
      captureHealth: manifest.captureHealth,
      events: records.length,
    },
    null,
    2,
  ),
);
