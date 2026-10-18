import { randomBytes } from "node:crypto";
import { readFile, writeFile } from "node:fs/promises";
let env = await readFile(".env.example", "utf8");
env = env.replace(/replace-with-[a-z0-9-]+/g, () =>
  randomBytes(32).toString("hex"),
);
await writeFile(".env", env, { flag: "wx", mode: 0o600 });
console.log(
  "Created .env with fresh credentials. Existing configurations are never overwritten.",
);
