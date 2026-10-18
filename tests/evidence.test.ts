import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtemp, readFile, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { randomUUID } from "node:crypto";
import { DuckDBInstance } from "@duckdb/node-api";
import { Evidence } from "../packages/core/evidence.js";
import { hash } from "../packages/core/util.js";

test("raw records retain precision and mixed event shapes round-trip through Parquet", async () => {
  const dir = await mkdtemp(join(tmpdir(), "verklikker-evidence-test-"));
  try {
    const e = new Evidence(dir, randomUUID(), randomUUID(), 1024 * 1024);
    await e.init();
    const original = '{"timestamp":1780000000000000001,"eventName":"execve"}';
    e.event(
      "tracee",
      "execve",
      {
        processId: 1,
        args: [{ name: "argv", value: ["node", "script"] }],
        timestamp: 1780000000000000000,
      },
      original,
    );
    await e.flush();
    e.event("gateway", "dns", { host: "example.com", addresses: ["1.1.1.1"] });
    await e.flush();
    for (const a of e.artifacts)
      assert.equal(hash(await readFile(join(dir, a.id))), a.sha256);
    const raw = JSON.parse(
      await readFile(
        join(dir, e.artifacts.find((a) => a.kind === "raw")!.id),
        "utf8",
      ),
    );
    assert.equal(raw.record, original);
    const db = await DuckDBInstance.create(":memory:");
    const c = await db.connect();
    try {
      const paths = e.artifacts
        .filter((a) => a.kind === "index")
        .map((a) => `'${join(dir, a.id)}'`)
        .join(",");
      const rows = (
        await c.runAndReadAll(
          `SELECT kind,data FROM read_parquet([${paths}],union_by_name=true) ORDER BY sequence`,
        )
      ).getRowObjectsJson();
      assert.deepEqual(
        rows.map((r) => r.kind),
        ["execve", "dns"],
      );
    } finally {
      c.closeSync();
      db.closeSync();
    }
    assert.equal(e.artifacts.length, 6);
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});
test("artifact budgets reject before writing beyond the reservation", async () => {
  const dir = await mkdtemp(join(tmpdir(), "verklikker-budget-test-"));
  try {
    const e = new Evidence(dir, "run", "attempt", 3);
    await e.init();
    await e.put("one", Buffer.from("abc"), "text/plain", "raw");
    await assert.rejects(
      e.put("two", Buffer.from("d"), "text/plain", "raw"),
      /budget/,
    );
    assert.equal(e.artifacts.length, 1);
    assert.equal(e.bytes, 3);
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});
