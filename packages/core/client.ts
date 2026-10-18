import { createReadStream } from "node:fs";
import type { Artifact } from "../contracts/index.js";
export class Client {
  constructor(
    readonly base: string,
    readonly token: string,
  ) {
    if (!/^https?:\/\//.test(base))
      throw new Error("Use an HTTP(S) service URL");
  }
  async request(
    path: string,
    body?: unknown,
    method = body ? "POST" : "GET",
  ): Promise<any> {
    const res = await fetch(this.base.replace(/\/$/, "") + path, {
      method,
      headers: {
        authorization: `Bearer ${this.token}`,
        ...(body ? { "content-type": "application/json" } : {}),
      },
      body: body ? JSON.stringify(body) : undefined,
      signal: AbortSignal.timeout(30000),
    });
    if (!res.ok)
      throw new Error(
        `Service ${res.status}: ${(await res.text()).slice(0, 2000)}`,
      );
    return res.json();
  }
  async publish(runId: string, leaseToken: string, a: Artifact, path: string) {
    const prefix = `/internal/runs/${runId}`;
    const { url } = await this.request(prefix + "/artifacts", {
      leaseToken,
      artifact: a,
    });
    const response = await fetch(url, {
      method: "PUT",
      headers: {
        "content-type": a.mediaType,
        "content-length": String(a.size),
      },
      body: createReadStream(path),
      duplex: "half",
      signal: AbortSignal.timeout(240000),
    } as any);
    if (!response.ok)
      throw new Error(`Artifact upload failed: ${response.status}`);
    await this.request(`${prefix}/artifacts/${a.id}/commit`, { leaseToken });
  }
}
