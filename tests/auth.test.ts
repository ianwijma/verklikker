import { test } from "node:test";
import assert from "node:assert/strict";
import { Auth } from "../apps/api/auth.js";
import type { Database } from "../apps/api/db.js";
test("encrypted browser state rejects tampering, expiration and wrong secrets", () => {
  const db = {} as Database;
  const auth = new Auth(
    db,
    "https://identity.example",
    "verklikker",
    "a".repeat(32),
  );
  const state = auth.seal({
    expires: Date.now() + 60000,
    csrf: "csrf",
    token: "secret",
  });
  assert.equal(auth.unseal(state).token, "secret");
  const corrupt = Buffer.from(state, "base64url");
  corrupt[20] = corrupt[20]! ^ 1;
  assert.throws(() => auth.unseal(corrupt.toString("base64url")), /expired/);
  assert.throws(
    () => auth.unseal(auth.seal({ expires: Date.now() - 1 })),
    /expired/,
  );
  const wrong = new Auth(
    db,
    "https://identity.example",
    "verklikker",
    "b".repeat(32),
  );
  assert.throws(() => wrong.unseal(state), /expired/);
});
