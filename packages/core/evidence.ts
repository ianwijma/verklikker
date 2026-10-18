import { mkdir, writeFile, stat, rm } from "node:fs/promises";
import { createWriteStream } from "node:fs";
import { createReadStream } from "node:fs";
import { createHash } from "node:crypto";
import { copyFile } from "node:fs/promises";
import { join } from "node:path";
import { randomUUID } from "node:crypto";
import { once } from "node:events";
import { hash } from "./util.js";
import type { Artifact, EvidenceEvent } from "../contracts/index.js";
export class Evidence {
  sequence = 0;
  bytes = 0;
  artifacts: Artifact[] = [];
  constructor(
    readonly directory: string,
    readonly runId: string,
    readonly attemptId: string,
    readonly budget: number,
    private publish?: (artifact: Artifact, path: string) => Promise<void>,
  ) {}
  async init() {
    await mkdir(this.directory, { recursive: true, mode: 0o700 });
  }
  private raw: string[] = [];
  private normalized: EvidenceEvent[] = [];
  private buffered = 0;
  event(
    source: string,
    kind: string,
    data: Record<string, unknown>,
    raw?: unknown,
  ) {
    const now = new Date().toISOString();
    const sequence = ++this.sequence;
    const rawLine = JSON.stringify({
      sequence,
      source,
      receivedAt: now,
      record: raw ?? data,
    });
    const timestamp = typeof data.timestamp === "string" ? data.timestamp : now;
    const e: EvidenceEvent = {
      version: 1,
      runId: this.runId,
      attemptId: this.attemptId,
      source,
      sequence,
      timestamp,
      receivedAt: now,
      kind,
      data,
      rawRef: `raw:${sequence}`,
    };
    if (data.processEntityId !== undefined)
      e.processId = String(data.processEntityId);
    else if (data.processId !== undefined) e.processId = String(data.processId);
    if (data.parentEntityId !== undefined)
      e.parentId = String(data.parentEntityId);
    else if (data.parentProcessId !== undefined)
      e.parentId = String(data.parentProcessId);
    const size =
      Buffer.byteLength(rawLine) + Buffer.byteLength(JSON.stringify(e)) + 2;
    if (
      this.bytes + size > this.budget ||
      this.buffered + size > 8 * 1024 * 1024
    )
      throw new Error("Evidence byte budget exhausted");
    this.bytes += size;
    this.raw.push(rawLine);
    this.normalized.push(e);
    this.buffered += size;
  }
  get needsFlush() {
    return this.buffered >= 1024 * 1024;
  }
  async flush() {
    if (!this.raw.length) return;
    const raw = this.raw;
    const normalized = this.normalized;
    this.raw = [];
    this.normalized = [];
    this.buffered = 0;
    const start = normalized[0]!.sequence;
    await this.put(
      `raw-${start}.jsonl`,
      Buffer.from(raw.join("\n") + "\n"),
      "application/x-ndjson",
      "raw",
      false,
    );
    const normalizedFile = await this.put(
      `events-${start}.jsonl`,
      Buffer.from(normalized.map((v) => JSON.stringify(v)).join("\n") + "\n"),
      "application/x-ndjson",
      "events",
      false,
    );
    const { DuckDBInstance } = await import("@duckdb/node-api");
    const db = await DuckDBInstance.create(":memory:", {
      memory_limit: "256MB",
      threads: "1",
    });
    const c = await db.connect();
    const out = join(this.directory, randomUUID() + ".parquet");
    try {
      const input = join(this.directory, normalizedFile.id);
      const quote = (p: string) => "'" + p.replaceAll("'", "''") + "'";
      await c.run(
        `COPY (SELECT * FROM read_json(${quote(input)}, format='newline_delimited', maximum_object_size=16777216, columns={version:'INTEGER',runId:'VARCHAR',attemptId:'VARCHAR',source:'VARCHAR',sequence:'BIGINT',timestamp:'VARCHAR',receivedAt:'VARCHAR',kind:'VARCHAR',processId:'VARCHAR',parentId:'VARCHAR',data:'JSON',rawRef:'VARCHAR'})) TO ${quote(out)} (FORMAT PARQUET, COMPRESSION ZSTD)`,
      );
      await this.putFile(
        `events-${start}.parquet`,
        out,
        "application/vnd.apache.parquet",
        "index",
      );
    } finally {
      c.closeSync();
      db.closeSync();
      await rm(out, { force: true });
    }
  }
  async put(
    name: string,
    content: Buffer,
    mediaType: string,
    kind: string,
    count = true,
  ): Promise<Artifact> {
    if (count) {
      if (this.bytes + content.length > this.budget)
        throw new Error("Evidence byte budget exhausted");
      this.bytes += content.length;
    }
    const artifact: Artifact = {
      id: randomUUID(),
      name,
      size: content.length,
      sha256: hash(content),
      mediaType,
      kind,
    };
    const path = join(this.directory, artifact.id);
    await writeFile(path, content, { mode: 0o600 });
    this.artifacts.push(artifact);
    await this.publish?.(artifact, path);
    return artifact;
  }
  async putFile(
    name: string,
    path: string,
    mediaType: string,
    kind: string,
  ): Promise<Artifact> {
    const size = (await stat(path)).size;
    if (this.bytes + size > this.budget)
      throw new Error("Evidence byte budget exhausted");
    this.bytes += size;
    const digest = createHash("sha256");
    for await (const chunk of createReadStream(path)) digest.update(chunk);
    const artifact: Artifact = {
      id: randomUUID(),
      name,
      size,
      sha256: digest.digest("hex"),
      mediaType,
      kind,
    };
    const target = join(this.directory, artifact.id);
    await copyFile(path, target);
    this.artifacts.push(artifact);
    await this.publish?.(artifact, target);
    return artifact;
  }
}
