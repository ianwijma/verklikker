import { test } from "node:test";
import assert from "node:assert/strict";
import { randomUUID } from "node:crypto";
import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { Database } from "../../apps/api/db.js";
import { Storage } from "../../apps/api/storage.js";
import { Auth } from "../../apps/api/auth.js";
import { buildApp } from "../../apps/api/app.js";
import { Evidence } from "../../packages/core/evidence.js";
import { Client } from "../../packages/core/client.js";
import { runSpec } from "../../packages/contracts/index.js";

test(
  "real S3 upload, commit, indexed query and tenant-scoped downloads",
  { skip: !process.env.TEST_S3_ENDPOINT || !process.env.TEST_DATABASE_URL },
  async () => {
    const db = new Database(process.env.TEST_DATABASE_URL!);
    await db.migrate();
    const storage = new Storage(
      process.env.TEST_S3_BUCKET ?? "evidence",
      process.env.TEST_S3_ENDPOINT,
      process.env.TEST_S3_ENDPOINT,
    );
    await storage.init();
    const auth = new Auth(
      db,
      "http://identity.invalid",
      "verklikker",
      "integration-session-secret-at-least-32-characters",
    );
    const a = await db.tenant(randomUUID(), "storage-A"),
      b = await db.tenant(randomUUID(), "storage-B");
    const key = await auth.key(a.id, "integration", [
      "runs:read",
      "runs:write",
      "artifacts:read",
    ]);
    const other = await auth.key(b.id, "integration", [
      "runs:read",
      "runs:write",
      "artifacts:read",
    ]);
    const app = await buildApp({
      db,
      storage,
      auth,
      workerToken: "integration-worker",
      publicURL: "http://localhost:3000",
    });
    const dir = await mkdtemp(join(tmpdir(), "verklikker-storage-test-"));
    try {
      const base = await app.listen({ host: "127.0.0.1", port: 0 });
      const c = new Client(base, key.token),
        outsider = new Client(base, other.token),
        worker = new Client(base, "integration-worker");
      const input = await c.request("/v1/inputs", {
        name: "fixture.txt",
        data: Buffer.from("input-probe").toString("base64"),
      });
      const spec = runSpec.parse({
        image: "verklikker/base:local",
        argv: ["true"],
        inputs: [{ artifactId: input.id, path: "/work/input" }],
      });
      await assert.rejects(outsider.request("/v1/runs", { spec }), /404/);
      const submitted = await c.request("/v1/runs", { spec });
      const { run: job } = await worker.request("/internal/claim", {
        workerId: "storage-test",
        architecture: "x64",
      });
      assert.equal(job.id, submitted.id);
      const inputLink = await worker.request(
        `/internal/runs/${job.id}/inputs/${input.id}`,
        { leaseToken: job.leaseToken },
      );
      assert.equal(await (await fetch(inputLink.url)).text(), "input-probe");
      const evidence = new Evidence(
        dir,
        job.id,
        job.attempt_id,
        1024 * 1024,
        (a, path) => worker.publish(job.id, job.leaseToken, a, path),
      );
      await evidence.init();
      evidence.event("tracee", "execve", {
        processId: 42,
        processEntityId: 1001,
        parentEntityId: 1000,
        processName: "node",
        argv: ["node", "test"],
      });
      await evidence.flush();
      const events = await c.request(`/v1/runs/${job.id}/events`);
      assert.equal(events.length, 1);
      assert.equal(events[0].processId, "1001");
      assert.equal(events[0].data.processName, "node");
      const artifacts = await c.request(`/v1/runs/${job.id}/artifacts`);
      assert.equal(artifacts.length, 3);
      await assert.rejects(
        outsider.request(`/v1/artifacts/${artifacts[0].id}/download`),
        /404/,
      );
      await worker.request(`/internal/runs/${job.id}/finish`, {
        leaseToken: job.leaseToken,
        manifest: {
          version: 1,
          runId: job.id,
          attemptId: job.attempt_id,
          state: "completed",
          captureHealth: "healthy",
          exitCode: 0,
        },
      });
      const status = await c.request("/v1/runs/status", { ids: [job.id] });
      assert.equal(status[0].state, "completed");
    } finally {
      await app.close();
      for (const id of [a.id, b.id]) {
        const artifacts = (
          await db.pool.query(
            "SELECT object_key FROM artifacts WHERE tenant_id=$1",
            [id],
          )
        ).rows;
        for (const a of artifacts) await storage.delete(a.object_key);
        await db.pool.query("DELETE FROM artifacts WHERE tenant_id=$1", [id]);
        await db.pool.query("DELETE FROM runs WHERE tenant_id=$1", [id]);
        await db.pool.query("DELETE FROM api_keys WHERE tenant_id=$1", [id]);
        await db.pool.query("DELETE FROM audit WHERE tenant_id=$1", [id]);
        await db.pool.query("DELETE FROM tenants WHERE id=$1", [id]);
      }
      await db.pool.end();
      await rm(dir, { recursive: true, force: true });
    }
  },
);
