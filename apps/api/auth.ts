import { createRemoteJWKSet, jwtVerify } from "jose";
import {
  createCipheriv,
  createDecipheriv,
  randomBytes,
  randomUUID,
} from "node:crypto";
import type { FastifyRequest } from "fastify";
import { Database, Forbidden } from "./db.js";
import { hash, equal } from "../../packages/core/util.js";
export interface Identity {
  tenantId: string;
  scopes: string[];
  session: boolean;
  csrf?: string;
}
export class Unauthorized extends Error {
  statusCode = 401;
}
export class Auth {
  private jwks;
  private sessionKey: Buffer;
  constructor(
    readonly db: Database,
    readonly issuer: string,
    readonly audience: string,
    readonly sessionSecret: string,
    readonly internalIssuer = issuer,
  ) {
    if (sessionSecret.length < 32)
      throw new Error("SESSION_SECRET must contain at least 32 characters");
    this.sessionKey = Buffer.from(hash(sessionSecret), "hex");
    this.jwks = createRemoteJWKSet(
      new URL(internalIssuer + "/protocol/openid-connect/certs"),
    );
  }
  seal(data: unknown) {
    const iv = randomBytes(12),
      cipher = createCipheriv("aes-256-gcm", this.sessionKey, iv);
    const encrypted = Buffer.concat([
      cipher.update(JSON.stringify(data)),
      cipher.final(),
    ]);
    return Buffer.concat([iv, cipher.getAuthTag(), encrypted]).toString(
      "base64url",
    );
  }
  unseal(text: string): any {
    try {
      const b = Buffer.from(text, "base64url");
      const c = createDecipheriv(
        "aes-256-gcm",
        this.sessionKey,
        b.subarray(0, 12),
      );
      c.setAuthTag(b.subarray(12, 28));
      const value = JSON.parse(
        Buffer.concat([c.update(b.subarray(28)), c.final()]).toString(),
      );
      if (value.expires < Date.now()) throw new Error();
      return value;
    } catch {
      throw new Unauthorized("Session expired");
    }
  }
  async identify(request: FastifyRequest): Promise<Identity> {
    const authorization = request.headers.authorization;
    let token = authorization?.startsWith("Bearer ")
      ? authorization.slice(7)
      : undefined;
    let session = false,
      csrf: string | undefined;
    if (!token && request.cookies.session) {
      const s = this.unseal(request.cookies.session);
      token = s.token;
      csrf = s.csrf;
      session = true;
    }
    if (!token) throw new Unauthorized("Sign in to continue");
    if (token.startsWith("vk_")) {
      const [id, credential] = token.slice(3).split(".");
      if (!id || !credential || !/^[a-f0-9-]{36}$/.test(id))
        throw new Unauthorized("Invalid API key");
      const row = (
        await this.db.pool.query(
          "SELECT * FROM api_keys WHERE id=$1 AND revoked_at IS NULL",
          [id],
        )
      ).rows[0];
      if (!row || !equal(row.hash, hash(credential)))
        throw new Unauthorized("Invalid API key");
      return { tenantId: row.tenant_id, scopes: row.scopes, session: false };
    }
    let payload;
    try {
      ({ payload } = await jwtVerify(token, this.jwks, {
        issuer: this.issuer,
        audience: this.audience,
        algorithms: ["RS256"],
      }));
    } catch {
      throw new Unauthorized("Invalid access token");
    }
    if (!payload.sub) throw new Unauthorized("Token has no subject");
    const tenant = await this.db.tenant(
      this.issuer + "|" + payload.sub,
      String(payload.preferred_username ?? payload.sub),
    );
    return {
      tenantId: tenant.id,
      scopes: ["runs:read", "runs:write", "artifacts:read", "keys:manage"],
      session,
      csrf,
    };
  }
  async key(tenant: string, name: string, scopes: string[]) {
    const id = randomUUID(),
      credential = randomBytes(32).toString("base64url");
    await this.db.pool.query(
      "INSERT INTO api_keys(id,tenant_id,name,hash,scopes) VALUES($1,$2,$3,$4,$5)",
      [id, tenant, name, hash(credential), scopes],
    );
    return { id, token: `vk_${id}.${credential}` };
  }
}
