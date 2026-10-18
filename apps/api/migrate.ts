import { Database } from "./db.js";
import { required } from "../../packages/core/util.js";
const db = new Database(required("DATABASE_URL"));
try {
  await db.migrate();
} finally {
  await db.pool.end();
}
