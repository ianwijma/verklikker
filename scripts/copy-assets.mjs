import { copyFile, mkdir } from "node:fs/promises";
await mkdir("dist/apps/api", { recursive: true });
await copyFile("apps/api/schema.sql", "dist/apps/api/schema.sql");
