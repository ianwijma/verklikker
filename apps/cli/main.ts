import { Command } from "commander";
import { readFile, writeFile, mkdir } from "node:fs/promises";
import { createWriteStream, createReadStream } from "node:fs";
import { pipeline } from "node:stream/promises";
import { Readable } from "node:stream";
import { join, resolve } from "node:path";
import { homedir } from "node:os";
import { randomUUID, createHash } from "node:crypto";
import YAML from "yaml";
import { runSpec, npmSpec } from "../../packages/contracts/index.js";
import { doctor, run } from "../../packages/core/runner.js";
import { Client } from "../../packages/core/client.js";
import { sleep, hash } from "../../packages/core/util.js";
const program = new Command()
  .name("verklikker")
  .description(
    "Isolated execution with durable process, file and network evidence",
  )
  .option(
    "--server <url>",
    "Remote API URL",
    process.env.VERKLIKKER_URL ?? "http://localhost:3000",
  )
  .option(
    "--token <key>",
    "API key or OIDC access token",
    process.env.VERKLIKKER_TOKEN,
  );
async function client() {
  let token = program.opts().token;
  if (!token) {
    try {
      const saved = JSON.parse(
        await readFile(
          join(homedir(), ".config", "verklikker", "credentials.json"),
          "utf8",
        ),
      );
      if (saved.server === program.opts().server && saved.expires > Date.now())
        token = saved.token;
    } catch {}
  }
  if (!token) throw new Error("Run login or set VERKLIKKER_TOKEN");
  return new Client(program.opts().server, token);
}
const specFile = async (path: string) =>
  runSpec.parse(YAML.parse(await readFile(path, "utf8")));
program
  .command("doctor")
  .option("--runtime <directory>", "Runtime assets", "runtime")
  .action(async (opts) => {
    console.log(JSON.stringify(await doctor(resolve(opts.runtime)), null, 2));
  });
program
  .command("run <spec>")
  .option("--output <directory>", "Evidence directory")
  .option("--input <mapping...>", "Input UUID=local-file mappings")
  .action(async (path, opts) => {
    const spec = await specFile(path),
      inputs = new Map<string, string>(
        (opts.input ?? []).map((item: string) => {
          const index = item.indexOf("=");
          if (index < 0) throw new Error("Use UUID=path");
          return [item.slice(0, index), item.slice(index + 1)];
        }),
      );
    const controller = new AbortController();
    process.once("SIGINT", () => controller.abort());
    const directory = resolve(opts.output ?? join("artifacts", randomUUID()));
    const result = await run(spec, {
      directory,
      signal: controller.signal,
      input: async (id) => {
        const file = inputs.get(id);
        if (!file) throw new Error(`Missing --input mapping for ${id}`);
        return readFile(file);
      },
      status: (s) => console.error(s),
    });
    console.log(JSON.stringify({ directory, ...result }, null, 2));
    process.exitCode =
      result.state === "completed" && result.captureHealth === "healthy"
        ? 0
        : 1;
  });
program
  .command("npm <package>")
  .option("--remote", "Submit to the service")
  .option("--output <directory>", "Local output")
  .action(async (pkg, opts) => {
    const spec = npmSpec(pkg);
    if (opts.remote)
      console.log(
        JSON.stringify(
          await (await client()).request("/v1/runs", { spec }),
          null,
          2,
        ),
      );
    else {
      const directory = resolve(opts.output ?? join("artifacts", randomUUID()));
      const result = await run(spec, { directory });
      console.log(JSON.stringify({ directory, ...result }, null, 2));
      process.exitCode =
        result.state === "completed" && result.captureHealth === "healthy"
          ? 0
          : 1;
    }
  });
program
  .command("submit <spec>")
  .option("--idempotency-key <key>")
  .action(async (path, opts) =>
    console.log(
      JSON.stringify(
        await (
          await client()
        ).request("/v1/runs", {
          spec: await specFile(path),
          idempotencyKey: opts.idempotencyKey,
        }),
        null,
        2,
      ),
    ),
  );
program.command("batch <file>").action(async (path) => {
  const jobs = YAML.parse(await readFile(path, "utf8"));
  console.log(
    JSON.stringify(
      await (
        await client()
      ).request("/v1/batches", {
        jobs: jobs.map((spec: unknown) => ({ spec: runSpec.parse(spec) })),
      }),
      null,
      2,
    ),
  );
});
program
  .command("status <id>")
  .option("--wait", "Wait until terminal")
  .action(async (id, opts) => {
    const c = await client();
    for (;;) {
      const r = await c.request(`/v1/runs/${id}`);
      console.log(JSON.stringify(r, null, 2));
      if (
        !opts.wait ||
        !["queued", "booting", "running", "collecting"].includes(r.state)
      ) {
        process.exitCode =
          r.state === "completed" && r.capture_health === "healthy" ? 0 : 1;
        return;
      }
      await sleep(3000);
    }
  });
program
  .command("cancel <id>")
  .action(async (id) =>
    console.log(await (await client()).request(`/v1/runs/${id}/cancel`, {})),
  );
program
  .command("delete <id>")
  .description("Delete a terminal run and its evidence")
  .action(async (id) =>
    console.log(
      await (await client()).request(`/v1/runs/${id}`, undefined, "DELETE"),
    ),
  );
program.command("upload <path>").action(async (path) => {
  const bytes = await readFile(path);
  if (bytes.length > 64 * 1024 * 1024) throw new Error("Input exceeds 64 MiB");
  console.log(
    JSON.stringify(
      await (
        await client()
      ).request("/v1/inputs", {
        name: path.split("/").at(-1),
        data: bytes.toString("base64"),
      }),
      null,
      2,
    ),
  );
});
program.command("download <id> <directory>").action(async (id, directory) => {
  const c = await client();
  await mkdir(directory, { recursive: true, mode: 0o700 });
  const artifacts = await c.request(`/v1/runs/${id}/artifacts`);
  for (const a of artifacts) {
    if (!/^[a-f0-9-]{36}$/.test(a.id))
      throw new Error("Invalid artifact identifier");
    const { url } = await c.request(`/v1/artifacts/${a.id}/download`);
    const response = await fetch(url, { signal: AbortSignal.timeout(240000) });
    if (!response.ok || !response.body) throw new Error("Download failed");
    const path = join(directory, a.id);
    await pipeline(
      Readable.fromWeb(response.body as any),
      createWriteStream(path, { flags: "wx", mode: 0o600 }),
    );
    const h = createHash("sha256");
    for await (const b of createReadStream(path)) h.update(b);
    if (h.digest("hex") !== a.sha256)
      throw new Error(`Checksum mismatch: ${a.id}`);
  }
  const run = await c.request(`/v1/runs/${id}`);
  await writeFile(
    join(directory, "manifest.json"),
    JSON.stringify(run.manifest ?? run, null, 2),
    { mode: 0o600 },
  );
  await writeFile(
    join(directory, "artifacts.json"),
    JSON.stringify(artifacts, null, 2),
    { mode: 0o600 },
  );
  console.log(
    `Saved ${artifacts.length} artifacts. Files remain opaque and are not extracted.`,
  );
});
program.command("login").action(async () => {
  const server = program.opts().server;
  const config: any = await (await fetch(server + "/auth/config")).json();
  const start = await fetch(
    config.issuer + "/protocol/openid-connect/auth/device",
    {
      method: "POST",
      body: new URLSearchParams({
        client_id: config.clientId,
        scope: "openid profile",
      }),
    },
  );
  if (!start.ok) throw new Error("Device login unavailable");
  const device: any = await start.json();
  console.log(`Open ${device.verification_uri} and enter ${device.user_code}`);
  const deadline = Date.now() + device.expires_in * 1000;
  let delay = (device.interval ?? 5) * 1000;
  while (Date.now() < deadline) {
    await sleep(delay);
    const response = await fetch(
      config.issuer + "/protocol/openid-connect/token",
      {
        method: "POST",
        body: new URLSearchParams({
          client_id: config.clientId,
          grant_type: "urn:ietf:params:oauth:grant-type:device_code",
          device_code: device.device_code,
        }),
      },
    );
    const token: any = await response.json();
    if (response.ok) {
      const dir = join(homedir(), ".config", "verklikker");
      await mkdir(dir, { recursive: true, mode: 0o700 });
      await writeFile(
        join(dir, "credentials.json"),
        JSON.stringify({
          server,
          token: token.access_token,
          expires: Date.now() + token.expires_in * 1000,
        }),
        { mode: 0o600 },
      );
      console.log("Signed in.");
      return;
    }
    if (token.error === "slow_down") delay += 5000;
    else if (token.error !== "authorization_pending")
      throw new Error(token.error);
  }
  throw new Error("Login expired");
});
await program.parseAsync().catch((e) => {
  console.error(e.message);
  process.exitCode = 1;
});
