import { createReadStream, createWriteStream } from "node:fs";
import {
  mkdir,
  writeFile,
  readFile,
  chmod,
  chown,
  open,
  stat,
} from "node:fs/promises";
import { Duplex } from "node:stream";
import { createInterface } from "node:readline";
import { spawn } from "node:child_process";
import { randomUUID } from "node:crypto";
import { join } from "node:path";
import { Channel } from "../../packages/core/channel.js";
import { command, sleep } from "../../packages/core/util.js";
import { runSpec, type RunSpec } from "../../packages/contracts/index.js";

process.on("unhandledRejection", (e) => {
  console.error(e);
  process.exit(1);
});
const path = "/dev/virtio-ports/verklikker.control";
const channel = new Channel(
  Duplex.from({
    readable: createReadStream(path),
    writable: createWriteStream(path),
  }),
);
let spec: RunSpec;
let ca: string | undefined;
let specimen = "";
let collector = "";
let stopping = false;
let started = false;
let current: Awaited<ReturnType<typeof open>> | undefined;
let currentBytes = 0;
const inputs: { local: string; path: string; executable: boolean }[] = [];
let outgoing = Promise.resolve();
let queuedBytes = 0;
function send(frame: unknown) {
  const size = Buffer.byteLength(JSON.stringify(frame));
  queuedBytes += size;
  if (queuedBytes > 16 * 1024 * 1024) {
    void stop();
    throw new Error("Guest telemetry backpressure limit");
  }
  outgoing = outgoing
    .then(() => channel.send(frame))
    .finally(() => {
      queuedBytes -= size;
    });
  return outgoing;
}
async function stop() {
  stopping = true;
  if (specimen) await command("docker", ["kill", specimen]).catch(() => {});
}
async function file(
  name: string,
  path: string,
  kind = "capture",
  mediaType = "application/octet-stream",
) {
  const id = randomUUID();
  await send({ type: "file-start", id, name, kind, mediaType });
  for await (const part of createReadStream(path, {
    highWaterMark: 128 * 1024,
  }))
    await send({
      type: "file-data",
      id,
      data: Buffer.from(part).toString("base64"),
    });
  await send({ type: "file-end", id });
}
async function exportTo(bin: string, args: string[], path: string) {
  await new Promise<void>((ok, fail) => {
    const child = spawn(bin, args, { stdio: ["ignore", "pipe", "pipe"] });
    const out = createWriteStream(path);
    let error = "";
    child.stdout.pipe(out);
    child.stderr.on("data", (b) => {
      error += b;
    });
    child.on("error", fail);
    out.on("error", fail);
    child.on("close", (code) => {
      if (code !== 0) fail(new Error(error));
      else if (out.writableFinished) ok();
      else out.once("finish", ok);
    });
  });
}
async function execute() {
  if (started) throw new Error("Only one workload may run in a VM");
  started = true;
  await command("docker", ["info"]);
  for (const name of ["base", "npm", "tracee"]) {
    try {
      await stat(`/opt/images/${name}.tar`);
      await command("docker", ["load", "-i", `/opt/images/${name}.tar`], {
        timeout: 120000,
      });
    } catch (e) {
      if (name === "tracee") throw e;
    }
  }
  await mkdir("/var/lib/verklikker-capture-out", { recursive: true });
  await mkdir("/var/lib/verklikker-work", { recursive: true });
  await chmod("/var/lib/verklikker-work", 0o777);
  await mkdir("/var/lib/verklikker-capture", { recursive: true });
  try {
    await command("docker", ["image", "inspect", spec.image]);
  } catch {
    await command("docker", ["pull", spec.image], { timeout: 120000 });
  }
  const image = JSON.parse(
    await command("docker", ["image", "inspect", spec.image]),
  )[0];
  const args = [
    "create",
    "--name",
    "specimen",
    "--init",
    "--cap-drop=ALL",
    "--security-opt=no-new-privileges",
    "--pids-limit",
    String(spec.limits.pids),
    "--memory",
    `${Math.max(256, spec.limits.memoryMiB - 768)}m`,
    "--cpus",
    String(spec.limits.cpus),
    "--user",
    spec.user,
    "--workdir",
    spec.cwd,
    "--dns",
    "192.168.127.1",
    "--mount",
    "type=bind,source=/var/lib/verklikker-work,target=/work",
  ];
  const env = { ...spec.env };
  if (ca) {
    await writeFile("/run/ca.pem", ca);
    const roots = await readFile("/etc/ssl/certs/ca-certificates.crt", "utf8");
    await writeFile("/run/ca-bundle.pem", roots + "\n" + ca);
    Object.assign(env, {
      NODE_EXTRA_CA_CERTS: "/verklikker-ca.pem",
      SSL_CERT_FILE: "/verklikker-ca-bundle.pem",
      REQUESTS_CA_BUNDLE: "/verklikker-ca-bundle.pem",
      CURL_CA_BUNDLE: "/verklikker-ca-bundle.pem",
      GIT_SSL_CAINFO: "/verklikker-ca-bundle.pem",
    });
  }
  for (const [k, v] of Object.entries(env)) args.push("--env", `${k}=${v}`);
  args.push("--entrypoint", spec.argv[0]!, spec.image, ...spec.argv.slice(1));
  specimen = await command("docker", args);
  for (const input of inputs) {
    await command("docker", ["cp", input.local, `${specimen}:${input.path}`]);
  }
  if (ca) {
    await command("docker", [
      "cp",
      "/run/ca.pem",
      `${specimen}:/verklikker-ca.pem`,
    ]);
    await command("docker", [
      "cp",
      "/run/ca-bundle.pem",
      `${specimen}:/verklikker-ca-bundle.pem`,
    ]);
  }
  const traceeImage = (await readFile("/opt/tracee-image", "utf8")).trim();
  collector = await command("docker", [
    "create",
    "--name",
    "observer",
    "--pid=host",
    "--cgroupns=host",
    "--privileged",
    "--network=host",
    "-v",
    "/etc/os-release:/etc/os-release-host:ro",
    "-v",
    "/var/run:/var/run",
    "-v",
    "/var/lib/verklikker-capture:/captures",
    "verklikker/tracee:runtime",
    "--scope",
    `container=${specimen}`,
    "--events",
    "syscalls,sched_process_fork,sched_process_exec,sched_process_exit,vfs_read,vfs_readv,vfs_write,vfs_writev,security_file_open,security_mmap_file,net_packet_dns,net_flow_tcp_begin,net_flow_tcp_end",
    "--output",
    "json",
    "--capture",
    "read",
    "--capture",
    "write",
    "--capture",
    "exec",
    "--capture",
    "dir:/captures",
    "--server",
    "http-address=127.0.0.1:3366",
    "--server",
    "healthz",
    "--server",
    "metrics",
  ]);
  const trace = spawn("docker", ["start", "-a", collector], {
    stdio: ["ignore", "pipe", "pipe"],
  });
  let collectorError: Error | undefined;
  const lines = createInterface({ input: trace.stdout });
  lines.on("line", (line) => {
    try {
      const event = JSON.parse(line);
      if (event.eventName) void send({ type: "event", event, raw: line });
      else void send({ type: "diagnostic", text: line });
    } catch {
      collectorError = new Error("Unparseable collector output");
      void stop();
    }
  });
  trace.stderr.on("data", (b) => {
    void send({ type: "diagnostic", text: b.toString().slice(0, 65536) });
  });
  trace.on("error", (e) => {
    collectorError = e;
    void stop();
  });
  trace.on("exit", () => {
    if (!stopping) {
      collectorError = new Error("Collector exited");
      void stop();
    }
  });
  let ready = false;
  for (let i = 0; i < 300; i++) {
    if (collectorError) throw collectorError;
    try {
      ready = (
        await fetch("http://127.0.0.1:3366/healthz", {
          signal: AbortSignal.timeout(1000),
        })
      ).ok;
      if (ready) break;
    } catch {}
    await sleep(100);
  }
  if (!ready) throw new Error("Collector did not become healthy");
  let metricsBusy = false;
  let previousLost = 0;
  let metricsFailure = 0;
  let metricsVerified = false;
  let lastMetrics = "";
  async function checkMetrics() {
    if (metricsBusy) return;
    metricsBusy = true;
    try {
      const res = await fetch("http://127.0.0.1:3366/metrics", {
        signal: AbortSignal.timeout(1000),
      });
      if (!res.ok) throw new Error("metrics unavailable");
      const body = await res.text();
      lastMetrics = body;
      if (!/^tracee_ebpf_lostevents_total\s/m.test(body))
        throw new Error("Collector loss counters unavailable");
      metricsVerified = true;
      metricsFailure = 0;
      const loss = body
        .split("\n")
        .filter(
          (l) =>
            !l.startsWith("#") && /lost|dropped/.test(l.split(" ")[0] ?? ""),
        )
        .reduce((sum, l) => sum + (Number(l.split(" ").at(-1)) || 0), 0);
      if (loss > previousLost) {
        await send({ type: "loss", count: loss - previousLost });
        await stop();
      }
      previousLost = loss;
    } catch {
      if (++metricsFailure >= 3) {
        collectorError = new Error("Collector health lost");
        await stop();
      }
    } finally {
      metricsBusy = false;
    }
  }
  await checkMetrics();
  if (!metricsVerified || stopping)
    throw new Error("Collector loss accounting unavailable at startup");
  await send({
    type: "running",
    imageId: image.Id,
    repoDigests: image.RepoDigests,
    traceeImage,
    interventions: ca ? ["temporary certificate trust"] : [],
  });
  const metricsTimer = setInterval(() => {
    void checkMetrics();
  }, 1000);
  const exitCode = await new Promise<number>((ok, fail) => {
    const child = spawn("docker", ["start", "-a", specimen], {
      stdio: ["ignore", "pipe", "pipe"],
    });
    child.stdout.on("data", (b) => {
      void send({ type: "output", stream: "stdout", text: b.toString() });
    });
    child.stderr.on("data", (b) => {
      void send({ type: "output", stream: "stderr", text: b.toString() });
    });
    child.on("error", fail);
    child.on("exit", (code) => ok(code ?? 1));
  });
  if (!stopping) await sleep(spec.limits.observeSeconds * 1000);
  await send({ type: "collecting" });
  await stop();
  await checkMetrics();
  clearInterval(metricsTimer);
  await command("docker", ["stop", "-t", "5", collector]).catch(() => {});
  await new Promise<void>((ok) => {
    if (trace.exitCode !== null) {
      ok();
      return;
    }
    const timer = setTimeout(() => {
      collectorError = new Error("Collector output did not drain");
      trace.kill("SIGKILL");
      ok();
    }, 5000);
    trace.once("close", () => {
      clearTimeout(timer);
      ok();
    });
  });
  await outgoing;
  if (collectorError) throw collectorError;
  await writeFile("/var/lib/verklikker-capture-out/metrics.prom", lastMetrics);
  await file(
    "collector-metrics.prom",
    "/var/lib/verklikker-capture-out/metrics.prom",
    "diagnostic",
    "text/plain",
  );
  const diff = await command("docker", ["diff", specimen]);
  await writeFile("/var/lib/verklikker-capture-out/diff.txt", diff);
  await file(
    "filesystem-diff.txt",
    "/var/lib/verklikker-capture-out/diff.txt",
    "filesystem",
    "text/plain",
  );
  await exportTo(
    "docker",
    ["export", specimen],
    "/var/lib/verklikker-capture-out/rootfs.tar",
  );
  await file(
    "rootfs-final.tar",
    "/var/lib/verklikker-capture-out/rootfs.tar",
    "filesystem",
    "application/x-tar",
  );
  await exportTo(
    "tar",
    ["-C", "/var/lib/verklikker-work", "-cf", "-", "."],
    "/var/lib/verklikker-capture-out/workspace.tar",
  );
  await file(
    "workspace-final.tar",
    "/var/lib/verklikker-capture-out/workspace.tar",
    "filesystem",
    "application/x-tar",
  );
  await exportTo(
    "tar",
    ["-C", "/var/lib/verklikker-capture", "-cf", "-", "."],
    "/var/lib/verklikker-capture-out/capture.tar",
  );
  await file(
    "collector-files.tar",
    "/var/lib/verklikker-capture-out/capture.tar",
    "capture",
    "application/x-tar",
  );
  // Docker export excludes volumes, so preserve every anonymous image volume separately.
  const inspect = JSON.parse(await command("docker", ["inspect", specimen]))[0];
  for (const [i, mount] of (inspect.Mounts ?? []).entries()) {
    if (mount.Type !== "volume") continue;
    const target = `/var/lib/verklikker-capture-out/volume-${i}.tar`;
    await exportTo("tar", ["-C", mount.Source, "-cf", "-", "."], target);
    await file(`volume-${i}.tar`, target, "filesystem", "application/x-tar");
  }
  await send({ type: "complete", exitCode });
}
let chain = Promise.resolve();
channel.on("frame", (frame) => {
  if (frame.type === "stop") {
    void stop();
    return;
  }
  chain = chain
    .then(async () => {
      if (frame.type === "configure") {
        if (spec) throw new Error("Already configured");
        spec = runSpec.parse(frame.spec);
        ca = frame.ca;
        await mkdir("/var/lib/verklikker-inputs", { recursive: true });
      } else if (frame.type === "input-start") {
        if (!spec || started || current) throw new Error("Invalid input state");
        const entry = spec.inputs.find(
          (i) => i.artifactId === frame.artifactId && i.path === frame.path,
        );
        if (!entry) throw new Error("Unknown input");
        const local = join("/var/lib/verklikker-inputs", randomUUID());
        current = await open(local, "wx", entry.executable ? 0o755 : 0o644);
        currentBytes = 0;
        inputs.push({ local, path: entry.path, executable: entry.executable });
      } else if (frame.type === "input-data") {
        if (!current) throw new Error("No input open");
        const b = Buffer.from(frame.data, "base64");
        currentBytes += b.length;
        if (currentBytes > 64 * 1024 * 1024)
          throw new Error("Input exceeds budget");
        await current.write(b);
      } else if (frame.type === "input-end") {
        if (!current) throw new Error("No input open");
        await current.close();
        current = undefined;
      } else if (frame.type === "start") {
        if (!spec || current) throw new Error("Configuration incomplete");
        void execute().catch(async (e) => {
          await stop();
          await send({ type: "error", message: String(e) });
        });
      }
    })
    .catch(async (e) => {
      await stop();
      await send({ type: "error", message: String(e) });
    });
});
channel.on("failure", () => {
  void stop();
});
channel.on("closed", () => {
  void stop();
});
await send({ type: "ready", version: 1 });
