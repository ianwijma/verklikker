import { collectDeleted } from "./retention.js";
import { buildApp } from "./app.js";
import { Database } from "./db.js";
import { Storage } from "./storage.js";
import { Auth } from "./auth.js";
import { required } from "../../packages/core/util.js";
const db = new Database(required("DATABASE_URL"));
const storage = new Storage(required("S3_BUCKET"), process.env.S3_ENDPOINT);
const auth = new Auth(
  db,
  required("OIDC_ISSUER"),
  process.env.OIDC_CLIENT_ID ?? "verklikker",
  required("SESSION_SECRET"),
  process.env.OIDC_INTERNAL_ISSUER,
);
const app = await buildApp({
  db,
  storage,
  auth,
  workerToken: required("WORKER_TOKEN"),
  publicURL: process.env.PUBLIC_URL ?? "http://localhost:3000",
});
await storage.init();
let maintenanceBusy = false;
const timer = setInterval(async () => {
  if (maintenanceBusy) return;
  maintenanceBusy = true;
  try {
    await db.reap();
    await collectDeleted(db, storage);
  } catch (e) {
    app.log.error(e);
  } finally {
    maintenanceBusy = false;
  }
}, 10000);
async function shutdown() {
  clearInterval(timer);
  await app.close();
  await db.pool.end();
}
process.on("SIGTERM", () => void shutdown());
process.on("SIGINT", () => void shutdown());
await app.listen({
  host: process.env.HOST ?? "127.0.0.1",
  port: Number(process.env.PORT ?? 3000),
});
