import { createServer } from "node:http";
import { mkdtemp, readFile, rm } from "node:fs/promises";
import { spawn } from "node:child_process";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import assert from "node:assert/strict";
const dir = await mkdtemp(join(tmpdir(), "verklikker-proxy-test-"));
const server = createServer(async (req, res) => {
  let body = "";
  for await (const b of req) body += b;
  const data = JSON.parse(body);
  const result =
    req.url === "/proxy-resolve"
      ? {
          action: "mock",
          ip: "198.18.0.1",
          response: {
            status: 200,
            headers: { "content-type": "text/plain" },
            body: "mock-probe",
          },
        }
      : { ok: true };
  res.setHeader("content-type", "application/json");
  res.end(JSON.stringify(result));
});
await new Promise((ok) => server.listen(join(dir, "policy.sock"), ok));
const child = spawn(
  "docker",
  [
    "run",
    "--rm",
    "--network=host",
    "--name",
    "verklikker-proxy-smoke",
    "-v",
    `${dir}:${dir}`,
    "-v",
    resolve("native/proxy.py") + ":/opt/runtime/proxy.py:ro",
    "--entrypoint",
    "mitmdump",
    "verklikker/worker:0.1.0",
    "--mode",
    "socks5@127.0.0.1:0",
    "--set",
    `confdir=${dir}/ca`,
    "--set",
    `verklikker_socket=${dir}/policy.sock`,
    "--set",
    `verklikker_ready=${dir}/ready.json`,
    "--set",
    "connection_strategy=lazy",
    "--set",
    "upstream_cert=false",
    "-s",
    "/opt/runtime/proxy.py",
  ],
  { stdio: ["ignore", "pipe", "pipe"] },
);
let output = "";
child.stdout.on("data", (b) => (output += b));
child.stderr.on("data", (b) => (output += b));
try {
  let ready;
  for (let i = 0; i < 100; i++) {
    try {
      ready = JSON.parse(await readFile(join(dir, "ready.json"), "utf8"));
      break;
    } catch {}
    if (child.exitCode !== null) throw Error(output);
    await new Promise((ok) => setTimeout(ok, 100));
  }
  assert.ok(ready, output);
  const curl = spawn("curl", [
    "--silent",
    "--show-error",
    "--max-time",
    "10",
    "--socks5-hostname",
    ready.address,
    "--cacert",
    join(dir, "ca", "mitmproxy-ca-cert.pem"),
    "https://probe.example/check",
  ]);
  let text = "";
  curl.stdout.on("data", (b) => (text += b));
  curl.stderr.on("data", (b) => (text += b));
  await new Promise((ok) => curl.once("close", ok));
  assert.equal(curl.exitCode, 0, text + "\n" + output);
  assert.equal(text, "mock-probe");
  console.log("HTTPS mock passed with validated temporary CA");
} finally {
  const stop = spawn("docker", ["stop", "-t", "1", "verklikker-proxy-smoke"]);
  await new Promise((ok) => stop.once("close", ok));
  server.close();
  await rm(dir, { recursive: true, force: true });
}
