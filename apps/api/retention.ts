import type { Database } from "./db.js";
import type { Storage } from "./storage.js";
import { Conflict, Missing } from "./db.js";
import { terminalStates } from "../../packages/contracts/index.js";

export async function deleteRun(db: Database, tenant: string, id: string) {
  await db.tx(async (c) => {
    const r = (
      await c.query(
        "SELECT * FROM runs WHERE id=$1 AND tenant_id=$2 FOR UPDATE",
        [id, tenant],
      )
    ).rows[0];
    if (!r) throw new Missing("Run not found");
    if (!terminalStates.includes(r.state))
      throw new Conflict(
        "Cancel the run and wait for it to stop before deleting",
      );
    const bytes = (
      await c.query(
        "SELECT COALESCE(sum(size),0) bytes FROM artifacts WHERE run_id=$1 AND committed",
        [id],
      )
    ).rows[0].bytes;
    await c.query(
      "INSERT INTO pending_deletions(object_key) SELECT object_key FROM artifacts WHERE run_id=$1 ON CONFLICT DO NOTHING",
      [id],
    );
    await c.query("DELETE FROM artifacts WHERE run_id=$1", [id]);
    await c.query("DELETE FROM run_updates WHERE run_id=$1", [id]);
    await c.query("DELETE FROM runs WHERE id=$1", [id]);
    await c.query(
      "UPDATE tenants SET storage_used=storage_used-$2 WHERE id=$1",
      [tenant, bytes],
    );
    await c.query(
      "INSERT INTO audit(tenant_id,action,details) VALUES($1,$2,$3)",
      [tenant, "run.deleted", { runId: id }],
    );
  });
}
export async function deleteInput(db: Database, tenant: string, id: string) {
  await db.tx(async (c) => {
    await c.query("SELECT id FROM tenants WHERE id=$1 FOR UPDATE", [tenant]);
    const a = (
      await c.query(
        "SELECT * FROM artifacts WHERE id=$1 AND tenant_id=$2 AND kind='input' FOR UPDATE",
        [id, tenant],
      )
    ).rows[0];
    if (!a) throw new Missing("Input not found");
    const used = await c.query(
      "SELECT id FROM runs WHERE tenant_id=$1 AND NOT(state=ANY($2)) AND spec->'inputs' @> $3::jsonb LIMIT 1",
      [tenant, terminalStates, JSON.stringify([{ artifactId: id }])],
    );
    if (used.rowCount)
      throw new Conflict("Input is referenced by an unfinished run");
    await c.query(
      "INSERT INTO pending_deletions(object_key) VALUES($1) ON CONFLICT DO NOTHING",
      [a.object_key],
    );
    await c.query("DELETE FROM artifacts WHERE id=$1", [id]);
    await c.query(
      "UPDATE tenants SET storage_used=storage_used-$2 WHERE id=$1",
      [tenant, a.size],
    );
  });
}
export async function collectDeleted(db: Database, storage: Storage) {
  await db.tx(async (c) => {
    const abandoned = (
      await c.query(`SELECT a.* FROM artifacts a LEFT JOIN runs r ON r.id=a.run_id
      WHERE NOT a.committed AND a.created_at<now()-interval '16 minutes'
      AND (a.run_id IS NULL OR r.lease_hash IS NULL) FOR UPDATE OF a SKIP LOCKED LIMIT 100`)
    ).rows;
    for (const a of abandoned) {
      await c.query(
        "INSERT INTO pending_deletions(object_key,delete_after) VALUES($1,now()) ON CONFLICT DO NOTHING",
        [a.object_key],
      );
      await c.query("DELETE FROM artifacts WHERE id=$1", [a.id]);
      if (a.kind === "input")
        await c.query(
          "UPDATE tenants SET storage_used=storage_used-$2 WHERE id=$1",
          [a.tenant_id, a.size],
        );
    }
  });
  // Delay past presigned upload expiry so an in-flight upload cannot resurrect an object.
  const keys = (
    await db.pool.query(
      "SELECT object_key FROM pending_deletions WHERE delete_after<now() LIMIT 100",
    )
  ).rows;
  for (const { object_key } of keys) {
    await storage.delete(object_key);
    await db.pool.query("DELETE FROM pending_deletions WHERE object_key=$1", [
      object_key,
    ]);
  }
}
