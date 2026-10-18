import pg from "pg";
import { readFile } from "node:fs/promises";
import { randomUUID } from "node:crypto";
import { hash, secret, equal } from "../../packages/core/util.js";
import {
  runSpec,
  terminalStates,
  type RunSpec,
  type WorkerCapacity,
  workerCapacity,
} from "../../packages/contracts/index.js";
export class Conflict extends Error {
  statusCode = 409;
}
export class Missing extends Error {
  statusCode = 404;
}
export class Forbidden extends Error {
  statusCode = 403;
}
export class Database {
  readonly pool: pg.Pool;
  constructor(url: string) {
    this.pool = new pg.Pool({ connectionString: url, max: 20 });
  }
  async migrate() {
    const sql = await readFile(
      new URL("./schema.sql", import.meta.url),
      "utf8",
    );
    await this.tx(async (c) => {
      await c.query("SELECT pg_advisory_xact_lock(72814451)");
      await c.query(sql);
    });
  }
  async tx<T>(fn: (c: pg.PoolClient) => Promise<T>): Promise<T> {
    const c = await this.pool.connect();
    try {
      await c.query("BEGIN");
      const result = await fn(c);
      await c.query("COMMIT");
      return result;
    } catch (e) {
      await c.query("ROLLBACK");
      throw e;
    } finally {
      c.release();
    }
  }
  async tenant(subject: string, name: string) {
    return (
      await this.pool.query(
        "INSERT INTO tenants(id,subject,name) VALUES($1,$2,$3) ON CONFLICT(subject) DO UPDATE SET name=excluded.name RETURNING *",
        [randomUUID(), subject, name],
      )
    ).rows[0];
  }
  async submit(tenant: string, input: RunSpec, key?: string, batch?: string) {
    const spec = runSpec.parse(input);
    const digest = hash(JSON.stringify(spec));
    if (
      spec.limits.cpus > 8 ||
      spec.limits.memoryMiB > 16384 ||
      spec.limits.timeoutSeconds > 3600 ||
      spec.limits.evidenceBytes > 20 * 1024 ** 3
    )
      throw new Forbidden("Remote run exceeds service ceilings");
    return this.tx(async (c) => {
      await c.query("SELECT id FROM tenants WHERE id=$1 FOR UPDATE", [tenant]);
      if (key) {
        const existing = (
          await c.query(
            "SELECT * FROM runs WHERE tenant_id=$1 AND idempotency_key=$2",
            [tenant, key],
          )
        ).rows[0];
        if (existing) {
          if (existing.spec_hash !== digest)
            throw new Conflict(
              "Idempotency key already has a different specification",
            );
          return existing;
        }
      }
      if (
        Number(
          (
            await c.query(
              "SELECT count(*) FROM runs WHERE tenant_id=$1 AND state='queued'",
              [tenant],
            )
          ).rows[0].count,
        ) >= 5000
      )
        throw new Conflict("Tenant queue limit reached");
      for (const input of spec.inputs)
        if (
          !(
            await c.query(
              "SELECT id FROM artifacts WHERE id=$1 AND tenant_id=$2 AND kind='input' AND committed",
              [input.artifactId, tenant],
            )
          ).rowCount
        )
          throw new Missing("Input artifact unavailable");
      const row = (
        await c.query(
          "INSERT INTO runs(id,tenant_id,spec,spec_hash,idempotency_key,batch_id) VALUES($1,$2,$3,$4,$5,$6) RETURNING *",
          [randomUUID(), tenant, spec, digest, key, batch],
        )
      ).rows[0];
      await c.query(
        "INSERT INTO audit(tenant_id,action,details) VALUES($1,$2,$3)",
        [tenant, "run.submitted", { runId: row.id }],
      );
      return row;
    });
  }
  async get(tenant: string, id: string) {
    const row = (
      await this.pool.query("SELECT * FROM runs WHERE id=$1 AND tenant_id=$2", [
        id,
        tenant,
      ])
    ).rows[0];
    if (!row) throw new Missing("Run not found");
    return row;
  }
  async claim(
    worker: string,
    architecture: string,
    capacity: WorkerCapacity = workerCapacity.parse({}),
  ) {
    return this.tx(async (c) => {
      const tenant = (
        await c.query(
          `SELECT t.* FROM tenants t WHERE active < concurrency AND EXISTS (
        SELECT 1 FROM runs r WHERE r.tenant_id=t.id AND state='queued' AND (spec->>'architecture' IS NULL OR spec->>'architecture'=$1)
        AND (spec->'limits'->>'evidenceBytes')::bigint <= t.storage_limit-t.storage_used-t.storage_reserved
        AND (spec->'limits'->>'cpus')::int <= $2 AND (spec->'limits'->>'memoryMiB')::int <= $3
        AND (spec->'limits'->>'diskBytes')::bigint <= $4 AND (spec->'limits'->>'evidenceBytes')::bigint <= $5)
        ORDER BY last_scheduled,created_at FOR UPDATE SKIP LOCKED LIMIT 1`,
          [
            architecture,
            capacity.cpus,
            capacity.memoryMiB,
            capacity.diskBytes,
            capacity.evidenceBytes,
          ],
        )
      ).rows[0];
      if (!tenant) return null;
      const row = (
        await c.query(
          `SELECT * FROM runs WHERE tenant_id=$1 AND state='queued' AND (spec->>'architecture' IS NULL OR spec->>'architecture'=$2)
        AND (spec->'limits'->>'evidenceBytes')::bigint <= $3
        AND (spec->'limits'->>'cpus')::int <= $4 AND (spec->'limits'->>'memoryMiB')::int <= $5
        AND (spec->'limits'->>'diskBytes')::bigint <= $6 AND (spec->'limits'->>'evidenceBytes')::bigint <= $7 ORDER BY created_at FOR UPDATE SKIP LOCKED LIMIT 1`,
          [
            tenant.id,
            architecture,
            Number(tenant.storage_limit) -
              Number(tenant.storage_used) -
              Number(tenant.storage_reserved),
            capacity.cpus,
            capacity.memoryMiB,
            capacity.diskBytes,
            capacity.evidenceBytes,
          ],
        )
      ).rows[0];
      if (!row) return null;
      const token = secret();
      const attempt = randomUUID();
      const run = (
        await c.query(
          "UPDATE runs SET state='booting', started_at=now(),attempt_id=$2,worker_id=$3,lease_hash=$4,lease_expires=now()+interval '30 seconds' WHERE id=$1 RETURNING *",
          [row.id, attempt, worker, hash(token)],
        )
      ).rows[0];
      await c.query(
        "UPDATE tenants SET active=active+1, storage_reserved=storage_reserved+$2, last_scheduled=now() WHERE id=$1",
        [tenant.id, row.spec.limits.evidenceBytes],
      );
      return { ...run, leaseToken: token };
    });
  }
  async lease(
    c: pg.Pool | pg.PoolClient,
    id: string,
    token: string,
    lock = false,
  ) {
    const row = (
      await c.query(
        `SELECT * FROM runs WHERE id=$1 ${lock ? "FOR UPDATE" : ""}`,
        [id],
      )
    ).rows[0];
    if (
      !row ||
      !row.lease_hash ||
      !equal(row.lease_hash, hash(token)) ||
      new Date(row.lease_expires).getTime() <= Date.now() ||
      terminalStates.includes(row.state)
    )
      throw new Conflict("Lease expired or invalid");
    return row;
  }
  async heartbeat(id: string, token: string, state?: string) {
    return this.tx(async (c) => {
      const run = await this.lease(c, id, token, true);
      const stages = ["booting", "running", "collecting"];
      if (
        state &&
        (!stages.includes(state) ||
          stages.indexOf(state) < stages.indexOf(run.state))
      )
        throw new Conflict("Invalid state transition");
      await c.query(
        "UPDATE runs SET lease_expires=now()+interval '30 seconds',state=COALESCE($2,state) WHERE id=$1",
        [id, state],
      );
      return { cancel: run.cancel_requested, leaseSeconds: 30 };
    });
  }
  async finish(id: string, token: string, manifest: any) {
    return this.tx(async (c) => {
      const r = await this.lease(c, id, token, true);
      if (
        !terminalStates.includes(manifest.state) ||
        manifest.runId !== id ||
        manifest.attemptId !== r.attempt_id
      )
        throw new Conflict("Invalid result identity");
      const size = Number(
        (
          await c.query(
            "SELECT COALESCE(sum(size),0) AS bytes FROM artifacts WHERE run_id=$1 AND committed",
            [id],
          )
        ).rows[0].bytes,
      );
      await c.query(
        "UPDATE runs SET state=$2,capture_health=$3,exit_code=$4,reason=$5,manifest=$6,ended_at=now(),lease_hash=NULL WHERE id=$1",
        [
          id,
          r.cancel_requested ? "cancelled" : manifest.state,
          manifest.captureHealth,
          manifest.exitCode,
          manifest.reason,
          manifest,
        ],
      );
      await c.query(
        "UPDATE tenants SET active=active-1,storage_reserved=storage_reserved-$2,storage_used=storage_used+$3 WHERE id=$1",
        [r.tenant_id, r.spec.limits.evidenceBytes, size],
      );
      await c.query(
        "INSERT INTO audit(tenant_id,action,details) VALUES($1,$2,$3)",
        [r.tenant_id, "run.finished", { runId: id, state: manifest.state }],
      );
    });
  }
  async cancel(tenant: string, id: string) {
    await this.get(tenant, id);
    await this.pool.query(
      "UPDATE runs SET cancel_requested=true,state=CASE WHEN state='queued' THEN 'cancelled' ELSE state END,ended_at=CASE WHEN state='queued' THEN now() ELSE ended_at END WHERE id=$1 AND tenant_id=$2 AND NOT(state=ANY($3))",
      [id, tenant, terminalStates],
    );
  }
  async reap() {
    return this.tx(async (c) => {
      const rows = (
        await c.query(
          "SELECT * FROM runs WHERE lease_hash IS NOT NULL AND lease_expires < now() FOR UPDATE SKIP LOCKED",
        )
      ).rows;
      for (const r of rows) {
        const bytes = Number(
          (
            await c.query(
              "SELECT COALESCE(sum(size),0) AS bytes FROM artifacts WHERE run_id=$1 AND committed",
              [r.id],
            )
          ).rows[0].bytes,
        );
        await c.query(
          "UPDATE runs SET state='interrupted',capture_health='incomplete',reason='Worker lease expired',lease_hash=NULL,ended_at=now() WHERE id=$1",
          [r.id],
        );
        await c.query(
          "UPDATE tenants SET active=active-1,storage_reserved=storage_reserved-$2,storage_used=storage_used+$3 WHERE id=$1",
          [r.tenant_id, r.spec.limits.evidenceBytes, bytes],
        );
      }
      return rows.length;
    });
  }
}
