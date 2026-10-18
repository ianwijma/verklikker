import { test } from "node:test";
import assert from "node:assert/strict";
import { randomUUID } from "node:crypto";
import { Database } from "../../apps/api/db.js";
import { Auth } from "../../apps/api/auth.js";
import { buildApp } from "../../apps/api/app.js";
import { Storage } from "../../apps/api/storage.js";
import { runSpec, workerCapacity } from "../../packages/contracts/index.js";
import { deleteRun } from "../../apps/api/retention.js";

const url = process.env.TEST_DATABASE_URL;
test(
  "PostgreSQL tenancy, atomic claims, quotas, leases, revocation and retention",
  { skip: !url },
  async (t) => {
    const db = new Database(url!);
    await db.migrate();
    const a = await db.tenant("test-a-" + randomUUID(), "A"),
      b = await db.tenant("test-b-" + randomUUID(), "B");
    const auth = new Auth(
      db,
      "http://oidc.invalid/realm",
      "verklikker",
      "integration-session-secret-at-least-32-characters",
    );
    const tokenA = await auth.key(a.id, "test", [
        "runs:read",
        "runs:write",
        "artifacts:read",
      ]),
      tokenB = await auth.key(b.id, "test", [
        "runs:read",
        "runs:write",
        "artifacts:read",
      ]);
    const app = await buildApp({
      db,
      auth,
      storage: new Storage("test"),
      workerToken: "worker-test-token",
      publicURL: "http://localhost:3000",
    });
    const spec = runSpec.parse({
      image: "verklikker/base:local",
      argv: ["true"],
    });
    const headers = { authorization: "Bearer " + tokenA.token };
    let runId = "";
    try {
      await t.test(
        "idempotency is tenant-scoped; cross-tenant reads and cancels are hidden",
        async () => {
          const create = await app.inject({
            method: "POST",
            url: "/v1/runs",
            headers,
            payload: { spec, idempotencyKey: "same" },
          });
          assert.equal(create.statusCode, 201);
          runId = create.json().id;
          const repeated = await app.inject({
            method: "POST",
            url: "/v1/runs",
            headers,
            payload: { spec, idempotencyKey: "same" },
          });
          assert.equal(repeated.json().id, runId);
          const changed = await app.inject({
            method: "POST",
            url: "/v1/runs",
            headers,
            payload: {
              spec: { ...spec, argv: ["false"] },
              idempotencyKey: "same",
            },
          });
          assert.equal(changed.statusCode, 409);
          for (const [method, path] of [
            ["GET", `/v1/runs/${runId}`],
            ["POST", `/v1/runs/${runId}/cancel`],
            ["GET", `/v1/runs/${runId}/artifacts`],
          ] as const)
            assert.equal(
              (
                await app.inject({
                  method,
                  url: path,
                  headers: { authorization: "Bearer " + tokenB.token },
                  ...(method === "POST" ? { payload: {} } : {}),
                })
              ).statusCode,
              404,
            );
          assert.equal(
            (
              await app.inject({
                method: "POST",
                url: "/internal/claim",
                headers,
                payload: { workerId: "attacker", architecture: "x64" },
              })
            ).statusCode,
            401,
          );
        },
      );
      await t.test(
        "concurrent workers never claim a job twice and reservations enforce concurrency",
        async () => {
          await db.pool.query("UPDATE tenants SET concurrency=1 WHERE id=$1", [
            a.id,
          ]);
          await db.submit(a.id, spec, "second");
          const claims = (
            await Promise.all(
              Array.from({ length: 8 }, (_, i) => db.claim("w" + i, "x64")),
            )
          ).filter(Boolean);
          assert.equal(claims.length, 1);
          const job = claims[0];
          assert.equal(job.id, runId);
          await assert.rejects(db.heartbeat(job.id, "invalid"), /Lease/);
          await assert.rejects(deleteRun(db, a.id, job.id), /Cancel/);
          await db.heartbeat(job.id, job.leaseToken, "running");
          await assert.rejects(
            db.heartbeat(job.id, job.leaseToken, "booting"),
            /transition/,
          );
          await db.cancel(a.id, job.id);
          assert.equal(
            (await db.heartbeat(job.id, job.leaseToken)).cancel,
            true,
          );
          await db.finish(job.id, job.leaseToken, {
            runId: job.id,
            attemptId: job.attempt_id,
            state: "cancelled",
            captureHealth: "incomplete",
            exitCode: null,
          });
          await assert.rejects(db.finish(job.id, job.leaseToken, {}), /Lease/);
          const tenant = (
            await db.pool.query("SELECT * FROM tenants WHERE id=$1", [a.id])
          ).rows[0];
          assert.equal(tenant.active, 0);
          assert.equal(Number(tenant.storage_reserved), 0);
          await deleteRun(db, a.id, job.id);
          await assert.rejects(db.get(a.id, job.id), /not found/);
        },
      );
      await t.test(
        "expired leases preserve incomplete status and capacity-incompatible jobs stay queued",
        async () => {
          const job = await db.claim("expired", "x64");
          assert.ok(job);
          await db.pool.query(
            "UPDATE runs SET lease_expires=now()-interval '1 second' WHERE id=$1",
            [job.id],
          );
          assert.equal(await db.reap(), 1);
          assert.equal((await db.get(a.id, job.id)).state, "interrupted");
          await assert.rejects(db.heartbeat(job.id, job.leaseToken), /Lease/);
          const big = await db.submit(
            a.id,
            runSpec.parse({ ...spec, limits: { ...spec.limits, cpus: 4 } }),
          );
          assert.equal(await db.claim("small", "x64"), null);
          const sized = await db.claim(
            "large",
            "x64",
            workerCapacity.parse({ cpus: 4 }),
          );
          assert.equal(sized.id, big.id);
          await db.finish(sized.id, sized.leaseToken, {
            runId: sized.id,
            attemptId: sized.attempt_id,
            state: "failed",
            captureHealth: "incomplete",
            exitCode: 1,
          });
        },
      );
      await t.test(
        "revoked API credentials stop working immediately",
        async () => {
          await db.pool.query(
            "UPDATE api_keys SET revoked_at=now() WHERE id=$1",
            [tokenA.id],
          );
          assert.equal(
            (await app.inject({ method: "GET", url: "/v1/runs", headers }))
              .statusCode,
            401,
          );
        },
      );
    } finally {
      await app.close();
      for (const id of [a.id, b.id]) {
        await db.pool.query("DELETE FROM artifacts WHERE tenant_id=$1", [id]);
        await db.pool.query("DELETE FROM runs WHERE tenant_id=$1", [id]);
        await db.pool.query("DELETE FROM api_keys WHERE tenant_id=$1", [id]);
        await db.pool.query("DELETE FROM audit WHERE tenant_id=$1", [id]);
        await db.pool.query("DELETE FROM tenants WHERE id=$1", [id]);
      }
      await db.pool.end();
    }
  },
);
