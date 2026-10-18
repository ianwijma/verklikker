import { openapi } from "./openapi.js";
import Fastify from "fastify";
import cookie from "@fastify/cookie";
import rateLimit from "@fastify/rate-limit";
import { randomUUID, createHash } from "node:crypto";
import { readFile } from "node:fs/promises";
import { resolve, sep, extname } from "node:path";
import { z } from "zod";
import {
  runSpec,
  submission,
  terminalStates,
  workerCapacity,
} from "../../packages/contracts/index.js";
import { secret, hash, equal } from "../../packages/core/util.js";
import { Database, Forbidden, Missing, Conflict } from "./db.js";
import { Auth, Unauthorized, type Identity } from "./auth.js";
import { Storage } from "./storage.js";
import { deleteRun, deleteInput } from "./retention.js";
import { queryEvidence } from "./query.js";
const uuid = z.uuid();
const artifactInput = z
  .object({
    id: uuid,
    name: z.string().max(512),
    size: z.number().int().nonnegative(),
    sha256: z.string().regex(/^[a-f0-9]{64}$/),
    mediaType: z.string().max(128),
    kind: z.enum([
      "raw",
      "events",
      "index",
      "filesystem",
      "packets",
      "capture",
      "diagnostic",
    ]),
  })
  .strict();
const publicRun = (r: any) => {
  const { lease_hash, worker_id, lease_expires, spec_hash, ...rest } = r;
  return rest;
};
export interface AppOptions {
  db: Database;
  storage: Storage;
  auth: Auth;
  workerToken: string;
  publicURL: string;
  identify?: (req: any) => Promise<Identity>;
  webDirectory?: string;
}
export async function buildApp(options: AppOptions) {
  const { db, storage, auth } = options;
  const app = Fastify({
    logger: {
      serializers: {
        req: (req) => ({
          method: req.method,
          url: req.url?.split("?")[0],
          remoteAddress: req.ip,
        }),
      },
      redact: [
        "req.headers.authorization",
        "req.headers.cookie",
        "res.headers.set-cookie",
      ],
    },
    bodyLimit: 2 * 1024 * 1024,
  });
  await app.register(cookie);
  await app.register(rateLimit, {
    max: 600,
    timeWindow: "1 minute",
    allowList: (req) => req.url.startsWith("/internal/"),
  });
  const identities = new WeakMap<object, Identity>();
  app.setErrorHandler((err: any, req, reply) => {
    if (err instanceof z.ZodError) {
      reply.code(400).send({ error: "Invalid request", issues: err.issues });
      return;
    }
    const code = err.statusCode ?? 500;
    if (code >= 500) req.log.error(err);
    reply
      .code(code)
      .send({ error: code >= 500 ? "Internal service error" : err.message });
  });
  app.addHook("onRequest", async (req) => {
    if (req.url.startsWith("/internal/")) {
      if (
        !equal(req.headers.authorization ?? "", `Bearer ${options.workerToken}`)
      )
        throw new Unauthorized("Worker authentication required");
      return;
    }
    if (!req.url.startsWith("/v1/")) return;
    const identity = await (options.identify ?? auth.identify.bind(auth))(req);
    identities.set(req, identity);
    if (identity.session && !["GET", "HEAD", "OPTIONS"].includes(req.method)) {
      if (
        req.headers.origin !== new URL(options.publicURL).origin ||
        !equal(String(req.headers["x-csrf-token"] ?? ""), identity.csrf ?? "")
      )
        throw new Forbidden("Invalid request origin or CSRF token");
    }
  });
  let uploads = 0;
  const uploading = new WeakSet<object>();
  app.addHook("preParsing", async (req, _reply, payload) => {
    if (req.method === "POST" && req.url.split("?")[0] === "/v1/inputs") {
      if (uploads >= 2)
        throw Object.assign(
          new Error("Input upload capacity reached; retry shortly"),
          { statusCode: 429 },
        );
      uploads++;
      uploading.add(req);
    }
    return payload;
  });
  app.addHook("onResponse", async (req) => {
    if (uploading.delete(req)) uploads--;
  });
  app.addHook("onSend", async (req, reply, payload) => {
    if (req.url.startsWith("/v1/")) reply.header("Cache-Control", "no-store");
    return payload;
  });
  const who = (req: object, scope: string) => {
    const identity = identities.get(req)!;
    if (!identity.scopes.includes(scope))
      throw new Forbidden("Credential lacks required scope");
    return identity.tenantId;
  };
  app.get("/openapi.json", async () => openapi);
  app.get("/health", async () => {
    await db.pool.query("SELECT 1");
    return { ok: true };
  });
  app.get("/auth/config", async () => ({
    issuer: auth.issuer,
    clientId: auth.audience,
  }));
  app.get("/auth/login", async (req, reply) => {
    const state = secret(),
      verifier = secret();
    reply.setCookie(
      "oauth",
      auth.seal({ state, verifier, expires: Date.now() + 300000 }),
      {
        httpOnly: true,
        sameSite: "lax",
        secure: options.publicURL.startsWith("https:"),
        path: "/auth",
        maxAge: 300,
      },
    );
    const url = new URL(auth.issuer + "/protocol/openid-connect/auth");
    url.search = new URLSearchParams({
      client_id: auth.audience,
      redirect_uri: options.publicURL + "/auth/callback",
      response_type: "code",
      scope: "openid profile",
      state,
      code_challenge: createHash("sha256").update(verifier).digest("base64url"),
      code_challenge_method: "S256",
    }).toString();
    return reply.redirect(url.toString());
  });
  app.get("/auth/callback", async (req, reply) => {
    const q = z
      .object({ code: z.string(), state: z.string() })
      .parse(req.query);
    const pending = auth.unseal(req.cookies.oauth ?? "");
    if (!equal(q.state, pending.state))
      throw new Unauthorized("OAuth state mismatch");
    const response = await fetch(
      auth.internalIssuer + "/protocol/openid-connect/token",
      {
        method: "POST",
        body: new URLSearchParams({
          grant_type: "authorization_code",
          client_id: auth.audience,
          code: q.code,
          code_verifier: pending.verifier,
          redirect_uri: options.publicURL + "/auth/callback",
        }),
      },
    );
    if (!response.ok) throw new Unauthorized("Token exchange failed");
    const token: any = await response.json();
    reply.clearCookie("oauth", { path: "/auth" });
    reply.setCookie(
      "session",
      auth.seal({
        token: token.access_token,
        csrf: secret(),
        expires: Date.now() + Math.min(Number(token.expires_in), 3600) * 1000,
      }),
      {
        httpOnly: true,
        secure: options.publicURL.startsWith("https:"),
        sameSite: "lax",
        path: "/",
        maxAge: Math.min(Number(token.expires_in), 3600),
      },
    );
    return reply.redirect("/");
  });
  app.get("/v1/me", async (req) => {
    const identity = identities.get(req)!;
    const tenant = (
      await db.pool.query(
        "SELECT id,name,concurrency,active,storage_used,storage_limit,storage_reserved FROM tenants WHERE id=$1",
        [identity.tenantId],
      )
    ).rows[0];
    return { tenant, csrf: identity.csrf };
  });
  app.post("/v1/logout", async (req, reply) => {
    reply.clearCookie("session", { path: "/" });
    return { ok: true };
  });
  app.get("/v1/runs", async (req) => {
    const tenant = who(req, "runs:read");
    return (
      await db.pool.query(
        "SELECT * FROM runs WHERE tenant_id=$1 ORDER BY created_at DESC LIMIT 200",
        [tenant],
      )
    ).rows.map(publicRun);
  });
  app.post("/v1/runs", async (req, reply) => {
    const body = submission.parse(req.body);
    return reply
      .code(201)
      .send(
        publicRun(
          await db.submit(
            who(req, "runs:write"),
            body.spec,
            body.idempotencyKey,
          ),
        ),
      );
  });
  app.post("/v1/runs/status", async (req) => {
    const b = z
      .object({ ids: z.array(uuid).min(1).max(5000) })
      .strict()
      .parse(req.body);
    return (
      await db.pool.query(
        "SELECT id,state,capture_health FROM runs WHERE tenant_id=$1 AND id=ANY($2)",
        [who(req, "runs:read"), b.ids],
      )
    ).rows;
  });
  app.post("/v1/batches", async (req, reply) => {
    const body = z
      .object({ jobs: z.array(submission).min(1).max(1000) })
      .strict()
      .parse(req.body);
    const tenant = who(req, "runs:write");
    const batchId = randomUUID();
    const results = [];
    for (const job of body.jobs) {
      try {
        results.push({
          run: publicRun(
            await db.submit(tenant, job.spec, job.idempotencyKey, batchId),
          ),
        });
      } catch (e) {
        results.push({ error: e instanceof Error ? e.message : String(e) });
      }
    }
    return reply.code(207).send({ batchId, results });
  });
  app.get("/v1/runs/:id", async (req) =>
    publicRun(
      await db.get(who(req, "runs:read"), uuid.parse((req.params as any).id)),
    ),
  );
  app.delete("/v1/runs/:id", async (req, reply) => {
    await deleteRun(
      db,
      who(req, "runs:write"),
      uuid.parse((req.params as any).id),
    );
    return reply.code(202).send({ ok: true });
  });
  app.delete("/v1/inputs/:id", async (req, reply) => {
    await deleteInput(
      db,
      who(req, "runs:write"),
      uuid.parse((req.params as any).id),
    );
    return reply.code(202).send({ ok: true });
  });
  app.post("/v1/runs/:id/cancel", async (req) => {
    await db.cancel(who(req, "runs:write"), uuid.parse((req.params as any).id));
    return { ok: true };
  });
  app.get("/v1/runs/:id/stream", async (req, reply) => {
    const tenant = who(req, "runs:read"),
      id = uuid.parse((req.params as any).id);
    await db.get(tenant, id);
    reply.hijack();
    reply.raw.writeHead(200, {
      "Content-Type": "text/event-stream",
      "Cache-Control": "no-store",
      "X-Accel-Buffering": "no",
    });
    let busy = false;
    const timer = setInterval(async () => {
      if (busy) return;
      busy = true;
      try {
        const r = await db.get(tenant, id);
        reply.raw.write(`data: ${JSON.stringify(publicRun(r))}\n\n`);
        if (terminalStates.includes(r.state)) {
          clearInterval(timer);
          reply.raw.end();
        }
      } catch {
        clearInterval(timer);
        reply.raw.end();
      } finally {
        busy = false;
      }
    }, 1000);
    req.raw.on("close", () => clearInterval(timer));
  });
  app.get("/v1/runs/:id/events", async (req) => {
    const q = z
      .object({
        kind: z.string().max(128).optional(),
        after: z.coerce.number().int().min(0).default(0),
        limit: z.coerce.number().int().min(1).max(500).default(100),
      })
      .parse(req.query);
    return queryEvidence(
      db,
      storage,
      who(req, "runs:read"),
      uuid.parse((req.params as any).id),
      q,
    );
  });
  app.get("/v1/runs/:id/artifacts", async (req) => {
    const tenant = who(req, "artifacts:read"),
      id = uuid.parse((req.params as any).id);
    await db.get(tenant, id);
    return (
      await db.pool.query(
        "SELECT id,name,size,sha256,media_type,kind FROM artifacts WHERE tenant_id=$1 AND run_id=$2 AND committed ORDER BY created_at",
        [tenant, id],
      )
    ).rows;
  });
  app.get("/v1/artifacts/:id/download", async (req, reply) => {
    const a = (
      await db.pool.query(
        "SELECT * FROM artifacts WHERE id=$1 AND tenant_id=$2 AND committed",
        [uuid.parse((req.params as any).id), who(req, "artifacts:read")],
      )
    ).rows[0];
    if (!a) throw new Missing("Artifact not found");
    return { url: await storage.getURL(a.object_key, a.name) };
  });
  app.post(
    "/v1/inputs",
    { bodyLimit: 90 * 1024 * 1024 },
    async (req, reply) => {
      const tenant = who(req, "runs:write");
      const body = z
        .object({
          name: z.string().max(255),
          data: z.string().max(90 * 1024 * 1024),
        })
        .strict()
        .parse(req.body);
      const b = Buffer.from(body.data, "base64");
      if (b.length > 64 * 1024 * 1024)
        throw new Conflict("Input exceeds 64 MiB");
      const id = randomUUID(),
        key = `${tenant}/inputs/${id}`;
      await db.tx(async (c) => {
        const t = (
          await c.query("SELECT * FROM tenants WHERE id=$1 FOR UPDATE", [
            tenant,
          ])
        ).rows[0];
        if (
          Number(t.storage_used) + Number(t.storage_reserved) + b.length >
          Number(t.storage_limit)
        )
          throw new Conflict("Storage quota reached");
        await c.query(
          "UPDATE tenants SET storage_used=storage_used+$2 WHERE id=$1",
          [tenant, b.length],
        );
        await c.query(
          "INSERT INTO artifacts(id,tenant_id,name,object_key,size,sha256,media_type,kind) VALUES($1,$2,$3,$4,$5,$6,'application/octet-stream','input')",
          [id, tenant, body.name, key, b.length, hash(b)],
        );
      });
      try {
        await storage.put(key, b, "application/octet-stream");
        await db.pool.query("UPDATE artifacts SET committed=true WHERE id=$1", [
          id,
        ]);
      } catch (e) {
        await db.tx(async (c) => {
          await c.query("DELETE FROM artifacts WHERE id=$1", [id]);
          await c.query(
            "UPDATE tenants SET storage_used=storage_used-$2 WHERE id=$1",
            [tenant, b.length],
          );
        });
        throw e;
      }
      return reply.code(201).send({ id, sha256: hash(b), size: b.length });
    },
  );
  app.get(
    "/v1/keys",
    async (req) =>
      (
        await db.pool.query(
          "SELECT id,name,scopes,created_at,revoked_at FROM api_keys WHERE tenant_id=$1",
          [who(req, "keys:manage")],
        )
      ).rows,
  );
  app.post("/v1/keys", async (req) => {
    const b = z
      .object({
        name: z.string().min(1).max(100),
        scopes: z
          .array(z.enum(["runs:read", "runs:write", "artifacts:read"]))
          .min(1),
      })
      .strict()
      .parse(req.body);
    return auth.key(who(req, "keys:manage"), b.name, b.scopes);
  });
  app.delete("/v1/keys/:id", async (req) => {
    await db.pool.query(
      "UPDATE api_keys SET revoked_at=now() WHERE id=$1 AND tenant_id=$2",
      [uuid.parse((req.params as any).id), who(req, "keys:manage")],
    );
    return { ok: true };
  });
  app.post("/internal/claim", async (req) => {
    const b = z
      .object({
        workerId: z.string().min(1).max(200),
        architecture: z.enum(["x64", "arm64"]),
        capacity: workerCapacity,
      })
      .strict()
      .parse(req.body);
    return { run: await db.claim(b.workerId, b.architecture, b.capacity) };
  });
  const leaseBody = z.object({ leaseToken: z.string().min(32) });
  app.post("/internal/runs/:id/heartbeat", async (req) => {
    const b = leaseBody
      .extend({
        state: z.enum(["booting", "running", "collecting"]).optional(),
      })
      .strict()
      .parse(req.body);
    return db.heartbeat(
      uuid.parse((req.params as any).id),
      b.leaseToken,
      b.state,
    );
  });
  app.post("/internal/runs/:id/artifacts", async (req) => {
    const b = leaseBody
      .extend({ artifact: artifactInput })
      .strict()
      .parse(req.body);
    const id = uuid.parse((req.params as any).id);
    const a = await db.tx(async (c) => {
      const r = await db.lease(c, id, b.leaseToken, true);
      const existing = (
        await c.query("SELECT * FROM artifacts WHERE id=$1 AND run_id=$2", [
          b.artifact.id,
          id,
        ])
      ).rows[0];
      if (existing) {
        if (existing.sha256 !== b.artifact.sha256)
          throw new Conflict("Artifact ID conflict");
        return existing;
      }
      const bytes = Number(
        (
          await c.query(
            "SELECT COALESCE(sum(size),0) bytes FROM artifacts WHERE run_id=$1",
            [id],
          )
        ).rows[0].bytes,
      );
      if (bytes + b.artifact.size > r.spec.limits.evidenceBytes)
        throw new Conflict("Evidence quota reached");
      const key = `${r.tenant_id}/${id}/${r.attempt_id}/${b.artifact.id}`;
      return (
        await c.query(
          "INSERT INTO artifacts(id,tenant_id,run_id,attempt_id,name,object_key,size,sha256,media_type,kind) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10) RETURNING *",
          [
            b.artifact.id,
            r.tenant_id,
            id,
            r.attempt_id,
            b.artifact.name,
            key,
            b.artifact.size,
            b.artifact.sha256,
            b.artifact.mediaType,
            b.artifact.kind,
          ],
        )
      ).rows[0];
    });
    return {
      url: await storage.putURL(a.object_key, Number(a.size), a.media_type),
    };
  });
  app.post("/internal/runs/:id/artifacts/:artifact/commit", async (req) => {
    const b = leaseBody.strict().parse(req.body),
      id = uuid.parse((req.params as any).id);
    const r = await db.lease(db.pool, id, b.leaseToken);
    const a = (
      await db.pool.query(
        "SELECT * FROM artifacts WHERE id=$1 AND run_id=$2 AND attempt_id=$3",
        [uuid.parse((req.params as any).artifact), id, r.attempt_id],
      )
    ).rows[0];
    if (!a) throw new Missing("Artifact not found");
    const head = await storage.head(a.object_key);
    if (head.ContentLength !== Number(a.size))
      throw new Conflict("Artifact length mismatch");
    await db.tx(async (c) => {
      await db.lease(c, id, b.leaseToken, true);
      await c.query("UPDATE artifacts SET committed=true WHERE id=$1", [a.id]);
    });
    return { ok: true };
  });
  app.post("/internal/runs/:id/inputs/:artifact", async (req) => {
    const b = leaseBody.strict().parse(req.body),
      r = await db.lease(
        db.pool,
        uuid.parse((req.params as any).id),
        b.leaseToken,
      ),
      id = uuid.parse((req.params as any).artifact);
    if (!r.spec.inputs.some((i: any) => i.artifactId === id))
      throw new Forbidden("Input is not part of this run");
    const a = (
      await db.pool.query(
        "SELECT * FROM artifacts WHERE id=$1 AND tenant_id=$2 AND committed",
        [id, r.tenant_id],
      )
    ).rows[0];
    if (!a) throw new Missing("Input unavailable");
    return {
      url: await storage.getURL(a.object_key, a.name),
      sha256: a.sha256,
    };
  });
  app.post("/internal/runs/:id/finish", async (req) => {
    const b = leaseBody
      .extend({
        manifest: z
          .object({
            version: z.literal(1),
            runId: uuid,
            attemptId: uuid,
            state: z.enum(terminalStates),
            captureHealth: z.enum(["healthy", "incomplete"]),
            exitCode: z.number().int().nullable(),
            reason: z.string().max(10000).optional(),
          })
          .passthrough(),
      })
      .strict()
      .parse(req.body);
    await db.finish(
      uuid.parse((req.params as any).id),
      b.leaseToken,
      b.manifest,
    );
    return { ok: true };
  });
  app.get("/internal/metrics", async (_req, reply) => {
    const rows = (
      await db.pool.query(
        "SELECT state,count(*)::int AS count FROM runs GROUP BY state",
      )
    ).rows;
    const tenants = (
      await db.pool.query(
        "SELECT count(*)::int AS count,COALESCE(sum(active),0) AS active,COALESCE(sum(storage_used),0) AS bytes FROM tenants",
      )
    ).rows[0];
    return reply
      .type("text/plain; version=0.0.4")
      .send(
        [
          "# TYPE verklikker_runs gauge",
          ...rows.map((r) => `verklikker_runs{state="${r.state}"} ${r.count}`),
          `verklikker_tenants ${tenants.count}`,
          `verklikker_active_vms ${tenants.active}`,
          `verklikker_storage_bytes ${tenants.bytes}`,
          "",
        ].join("\n"),
      );
  });
  app.get("/*", async (req, reply) => {
    if (/^\/(v1|internal|auth)\//.test(req.url))
      throw new Missing("Endpoint not found");
    const root = resolve(options.webDirectory ?? "dist/web");
    const relative = req.url.split("?")[0]!.slice(1);
    let path = resolve(root, relative || "index.html");
    if (path !== root && !path.startsWith(root + sep))
      throw new Missing("Not found");
    let body: Buffer;
    try {
      body = await readFile(path);
    } catch {
      path = resolve(root, "index.html");
      try {
        body = await readFile(path);
      } catch {
        throw new Missing("Build the web console first");
      }
    }
    reply.header(
      "Content-Security-Policy",
      "default-src 'self'; connect-src 'self'; style-src 'self'; img-src 'self' data:; object-src 'none'; base-uri 'none'; frame-ancestors 'none'",
    );
    return reply
      .type(
        (
          {
            ".html": "text/html",
            ".js": "text/javascript",
            ".css": "text/css",
            ".svg": "image/svg+xml",
          } as Record<string, string>
        )[extname(path)] ?? "application/octet-stream",
      )
      .send(body);
  });
  return app;
}
