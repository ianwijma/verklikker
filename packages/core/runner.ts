import {
  access,
  mkdir,
  mkdtemp,
  readFile,
  writeFile,
  rm,
  stat,
  open,
} from "node:fs/promises";
import { createReadStream } from "node:fs";
import { createHash, randomUUID } from "node:crypto";
import { join, resolve } from "node:path";
import { tmpdir, platform, arch } from "node:os";
import { createConnection } from "node:net";
import { lookup } from "node:dns/promises";
import { createServer } from "node:http";
import { spawn, type ChildProcess } from "node:child_process";
import { z } from "zod";
import {
  runSpec,
  knownGaps,
  type RunSpec,
  type EvidenceManifest,
  type Artifact,
  type RunState,
} from "../contracts/index.js";
import { command, sleep } from "./util.js";
import { Policy } from "./policy.js";
import { Channel } from "./channel.js";
import { Evidence } from "./evidence.js";

export interface Runtime {
  directory: string;
  gateway: string;
  qemu: string;
  image: string;
  kernel: string;
  initrd: string;
  acceleration: "kvm" | "hvf";
  architecture: "x64" | "arm64";
  provenance: Record<string, unknown>;
}
async function shaFile(path: string) {
  const h = createHash("sha256");
  for await (const b of createReadStream(path)) h.update(b);
  return h.digest("hex");
}
export async function doctor(directory = resolve("runtime")): Promise<Runtime> {
  if (
    !["linux", "darwin"].includes(platform()) ||
    !["x64", "arm64"].includes(arch())
  )
    throw new Error("Execution requires Linux/macOS on x64/arm64");
  if (platform() === "linux")
    await access("/dev/kvm", 6).catch(() => {
      throw new Error(
        "KVM is unavailable. Use a KVM-capable host or submit to a remote service. Direct-host execution is prohibited.",
      );
    });
  const architecture = arch() as "x64" | "arm64";
  const qemu = `qemu-system-${architecture === "x64" ? "x86_64" : "aarch64"}`;
  const version = await command(qemu, ["--version"]);
  const acceleration = platform() === "linux" ? "kvm" : "hvf";
  if (!(await command(qemu, ["-accel", "help"])).includes(acceleration))
    throw new Error(`QEMU lacks ${acceleration}`);
  const manifest = JSON.parse(
    await readFile(join(directory, architecture, "manifest.json"), "utf8"),
  );
  const paths = {
    image: join(directory, architecture, "rootfs.qcow2"),
    kernel: join(directory, architecture, "vmlinuz"),
    initrd: join(directory, architecture, "initrd"),
  };
  for (const [key, path] of Object.entries(paths))
    if (
      !manifest.sha256?.[key] ||
      (await shaFile(path)) !== manifest.sha256[key]
    )
      throw new Error(`Runtime checksum mismatch: ${key}`);
  const gateway = join(directory, "verklikker-gateway");
  await access(gateway, 1);
  return {
    directory,
    gateway,
    qemu,
    ...paths,
    architecture,
    acceleration,
    provenance: { ...manifest, qemu: version },
  };
}
export function qemuArgs(runtime: Runtime, spec: RunSpec, work: string) {
  const args = [
    "-no-user-config",
    "-nodefaults",
    "-display",
    "none",
    "-no-reboot",
    "-accel",
    runtime.acceleration,
    "-machine",
    runtime.architecture === "x64" ? "q35" : "virt",
    "-cpu",
    "host",
    "-smp",
    String(spec.limits.cpus),
    "-m",
    String(spec.limits.memoryMiB),
    "-kernel",
    runtime.kernel,
    "-initrd",
    runtime.initrd,
    "-append",
    `root=/dev/vda rw console=${runtime.architecture === "x64" ? "ttyS0" : "ttyAMA0"} systemd.unit=multi-user.target`,
    "-drive",
    `file=${join(work, "disk.qcow2")},format=qcow2,if=virtio`,
    "-chardev",
    `socket,id=control,path=${join(work, "control.sock")},server=on,wait=off`,
    "-device",
    "virtio-serial-pci",
    "-device",
    "virtserialport,chardev=control,name=verklikker.control",
    "-netdev",
    `stream,id=net,addr.type=unix,addr.path=${join(work, "network.sock")}`,
    "-device",
    "virtio-net-pci,netdev=net,mac=5a:94:ef:e4:0c:ee",
    "-serial",
    `file:${join(work, "boot.log")}`,
  ];
  if (runtime.acceleration === "kvm")
    args.push(
      "-sandbox",
      "on,obsolete=deny,elevateprivileges=deny,spawn=deny,resourcecontrol=deny",
    );
  return args;
}
export interface RunOptions {
  runtime?: Runtime;
  directory: string;
  runId?: string;
  attemptId?: string;
  signal?: AbortSignal;
  input?: (id: string) => Promise<Buffer>;
  publish?: (artifact: Artifact, path: string) => Promise<void>;
  protectedHosts?: string[];
  status?: (state: "booting" | "running" | "collecting") => void;
  protectedIPs?: string[];
}
export async function run(
  input: RunSpec,
  options: RunOptions,
): Promise<EvidenceManifest> {
  const spec = runSpec.parse(input);
  const runtime = options.runtime ?? (await doctor());
  if (spec.architecture && spec.architecture !== runtime.architecture)
    throw new Error(
      "Requested architecture does not match hardware; software emulation is prohibited",
    );
  const work = await mkdtemp(join(tmpdir(), "verklikker-"));
  const runId = options.runId ?? randomUUID(),
    attemptId = options.attemptId ?? randomUUID();
  const evidence = new Evidence(
    options.directory,
    runId,
    attemptId,
    spec.limits.evidenceBytes,
    options.publish,
  );
  await evidence.init();
  const startedAt = new Date().toISOString();
  const controller = new AbortController();
  let state: RunState = "booting",
    exitCode: number | null = null;
  let reason: string | undefined;
  let healthy = false;
  let dropped = 0;
  let finished = false;
  let stopping = false;
  let configured = false;
  let traceEvents = 0;
  let queuedFrameBytes = 0;
  const children: ChildProcess[] = [];
  const files = new Map<
    string,
    {
      path: string;
      handle: Awaited<ReturnType<typeof open>>;
      name: string;
      size: number;
      mediaType: string;
      kind: string;
    }
  >();
  const abort = (message: string, next: RunState = "failed") => {
    if (!controller.signal.aborted) {
      state = next;
      reason = message;
      controller.abort(new Error(message));
    }
  };
  const cancel = () => abort("Cancelled", "cancelled");
  options.signal?.addEventListener("abort", cancel, { once: true });
  if (options.signal?.aborted) cancel();
  const emit = (
    source: string,
    kind: string,
    data: Record<string, unknown>,
    raw?: unknown,
  ) => {
    try {
      evidence.event(source, kind, data, raw);
    } catch (e) {
      abort(String(e), "limit_reached");
    }
  };
  const policy = new Policy(
    spec.network,
    (data) => emit("gateway", String(data.kind), data),
    options.protectedIPs,
    options.protectedHosts,
  );
  const server = createServer(async (req, res) => {
    try {
      let body = "";
      for await (const b of req) {
        body += b;
        if (body.length > 1024 * 1024)
          throw new Error("Policy request too large");
      }
      const data = JSON.parse(body);
      let result: unknown;
      if (req.url === "/dns") {
        const d = z
          .object({ name: z.string().max(253), type: z.number().int() })
          .parse(data);
        result = await policy.dns(d.name, d.type);
      } else if (req.url === "/authorize") {
        const d = z
          .object({
            ip: z.string(),
            port: z.number().int().min(1).max(65535),
            protocol: z.enum(["tcp", "udp"]),
            host: z.string().optional(),
          })
          .parse(data);
        result = policy.decide(d.ip, d.port, d.protocol, d.host);
      } else if (req.url === "/proxy-resolve") {
        const d = z
          .object({
            host: z.string().max(253),
            port: z.number().int().min(1).max(65535),
          })
          .parse(data);
        const response = await policy.dns(d.host, 1);
        const ip =
          response.addresses[0] ?? (await policy.dns(d.host, 28)).addresses[0];
        result = ip
          ? { ...policy.decide(ip, d.port, "tcp", d.host), ip }
          : { action: "deny", reason: "DNS resolution failed" };
      } else if (req.url === "/proxy-event") {
        emit("proxy", "http", data);
        result = { ok: true };
      } else {
        res.writeHead(404).end();
        return;
      }
      res.setHeader("content-type", "application/json");
      res.end(JSON.stringify(result));
    } catch {
      res.writeHead(400).end('{"error":"Invalid policy request"}');
    }
  });
  let channel: Channel | undefined;
  let flushChain = Promise.resolve();
  let frameChain = Promise.resolve();
  const queueFlush = () => {
    flushChain = flushChain
      .then(() => evidence.flush())
      .catch((e) => abort(`Evidence flush failed: ${e}`, "limit_reached"));
  };
  const spawnChild = (bin: string, args: string[]) => {
    const child = spawn(bin, args, {
      stdio: ["ignore", "pipe", "pipe"],
      env: { PATH: process.env.PATH, LANG: "C.UTF-8", HOME: work },
    });
    children.push(child);
    child.on("error", (e) => abort(`${bin}: ${e.message}`));
    child.on("exit", (code) => {
      if (!stopping && !finished) abort(`${bin} exited unexpectedly (${code})`);
    });
    child.stderr?.on("data", (b) =>
      emit("runtime", "diagnostic", {
        tool: bin,
        text: b.toString().slice(0, 16384),
      }),
    );
    return child;
  };
  const waitFile = async (path: string) => {
    for (let i = 0; i < 600; i++) {
      if (controller.signal.aborted) throw controller.signal.reason;
      try {
        await access(path);
        return;
      } catch {}
      await sleep(100, controller.signal);
    }
    throw new Error(`Timed out waiting for ${path}`);
  };
  const startupTimer = setTimeout(
    () => abort("VM preparation timed out", "timed_out"),
    180000,
  );
  let workloadTimer: NodeJS.Timeout | undefined;
  let collectionTimer: NodeJS.Timeout | undefined;
  let checkingSpace = false;
  const spaceTimer = setInterval(async () => {
    if (checkingSpace) return;
    checkingSpace = true;
    try {
      let extra = 0;
      for (const name of ["network.pcap", "http.mitm", "boot.log"])
        extra += (await stat(join(work, name)).catch(() => ({ size: 0 }))).size;
      if (extra + evidence.bytes > evidence.budget)
        abort("External capture byte budget exhausted", "limit_reached");
    } finally {
      checkingSpace = false;
    }
  }, 1000);
  const interval = setInterval(() => {
    queueFlush();
  }, 5000);
  try {
    options.status?.("booting");
    await new Promise<void>((ok, fail) =>
      server.listen(join(work, "policy.sock"), () => ok()).once("error", fail),
    );
    let proxy = "";
    let ca: string | undefined;
    if (
      spec.network.tls === "intercept" ||
      spec.network.rules.some((r) => r.action === "mock")
    ) {
      const proxyProcess = spawnChild("mitmdump", [
        "--mode",
        "socks5@127.0.0.1:0",
        "--set",
        `confdir=${join(work, "mitm")}`,
        "--set",
        `verklikker_socket=${join(work, "policy.sock")}`,
        "--set",
        `verklikker_ready=${join(work, "proxy.json")}`,
        "--set",
        "connection_strategy=lazy",
        "--set",
        "upstream_cert=false",
        "-s",
        join(runtime.directory, "proxy.py"),
        "-w",
        join(work, "http.mitm"),
      ]);
      proxyProcess.stdout?.on("data", (b) =>
        emit("proxy", "diagnostic", { text: b.toString().slice(0, 16384) }),
      );
      await waitFile(join(work, "proxy.json"));
      proxy = JSON.parse(
        await readFile(join(work, "proxy.json"), "utf8"),
      ).address;
      if (
        spec.network.tls === "intercept" ||
        spec.network.rules.some((r) => r.action === "mock")
      ) {
        await waitFile(join(work, "mitm", "mitmproxy-ca-cert.pem"));
        ca = await readFile(
          join(work, "mitm", "mitmproxy-ca-cert.pem"),
          "utf8",
        );
      }
    }
    const gatewayConfig = {
      Socket: join(work, "network.sock"),
      PolicySocket: join(work, "policy.sock"),
      Capture: join(work, "network.pcap"),
      Proxy: proxy,
      Bytes: spec.network.bytes,
      BytesPerSecond: spec.network.bytesPerSecond,
      Connections: spec.network.connections,
    };
    await writeFile(join(work, "gateway.json"), JSON.stringify(gatewayConfig), {
      mode: 0o600,
    });
    const gateway = spawnChild(runtime.gateway, [
      "--config",
      join(work, "gateway.json"),
    ]);
    gateway.stdout?.on("data", (b) => {
      if (b.toString().includes('"type":"limit"'))
        abort("Network byte budget exhausted", "limit_reached");
    });
    await waitFile(join(work, "network.sock"));
    const info = JSON.parse(
      await command("qemu-img", ["info", "--output=json", runtime.image]),
    );
    if (info["virtual-size"] > spec.limits.diskBytes)
      throw new Error("Requested disk is smaller than the base runtime image");
    await command("qemu-img", [
      "create",
      "-f",
      "qcow2",
      "-F",
      "qcow2",
      "-b",
      resolve(runtime.image),
      join(work, "disk.qcow2"),
      String(spec.limits.diskBytes),
    ]);
    spawnChild(runtime.qemu, qemuArgs(runtime, spec, work));
    await waitFile(join(work, "control.sock"));
    const socket = createConnection(join(work, "control.sock"));
    channel = new Channel(socket);
    channel.on("failure", (e) => abort(`Guest channel failed: ${e}`));
    channel.on("closed", () => {
      if (!finished && !stopping) abort("Guest channel closed");
    });
    const completion = new Promise<void>((resolveDone) => {
      if (controller.signal.aborted) {
        resolveDone();
        return;
      }
      controller.signal.addEventListener("abort", () => resolveDone(), {
        once: true,
      });
      channel!.on("frame", (frame) => {
        const frameBytes = Buffer.byteLength(JSON.stringify(frame));
        queuedFrameBytes += frameBytes;
        if (queuedFrameBytes > 1024 * 1024) socket.pause();
        frameChain = frameChain
          .then(async () => {
            if (finished || controller.signal.aborted) return;
            if (
              typeof frame !== "object" ||
              frame === null ||
              typeof frame.type !== "string"
            )
              throw new Error("Malformed guest message");
            if (frame.type === "ready") {
              if (configured) throw new Error("Guest repeated readiness");
              configured = true;
              await channel!.send({ type: "configure", spec, ca });
              for (const file of spec.inputs) {
                const bytes = await options.input?.(file.artifactId);
                if (!bytes) throw new Error("Missing input provider");
                if (bytes.length > 64 * 1024 * 1024)
                  throw new Error("Input exceeds 64 MiB");
                await channel!.send({ type: "input-start", ...file });
                for (let i = 0; i < bytes.length; i += 128 * 1024)
                  await channel!.send({
                    type: "input-data",
                    data: bytes.subarray(i, i + 128 * 1024).toString("base64"),
                  });
                await channel!.send({ type: "input-end" });
              }
              await channel!.send({ type: "start" });
            } else if (frame.type === "running") {
              clearTimeout(startupTimer);
              healthy = true;
              state = "running";
              options.status?.("running");
              emit("runtime", "provenance", frame);
              workloadTimer = setTimeout(
                () => abort("Execution deadline exceeded", "timed_out"),
                (spec.limits.timeoutSeconds + spec.limits.observeSeconds) *
                  1000,
              );
            } else if (frame.type === "collecting") {
              clearTimeout(workloadTimer);
              collectionTimer = setTimeout(
                () =>
                  abort("Evidence collection deadline exceeded", "timed_out"),
                300000,
              );
              state = "collecting";
              options.status?.("collecting");
            } else if (frame.type === "event") {
              traceEvents++;
              emit(
                "tracee",
                String(frame.event?.eventName ?? "unknown"),
                frame.event ?? {},
                frame.raw ?? frame.event,
              );
            } else if (frame.type === "output") {
              emit("workload", String(frame.stream ?? "stdout"), {
                text: String(frame.text ?? ""),
              });
            } else if (frame.type === "diagnostic") {
              emit("collector", "diagnostic", frame);
            } else if (frame.type === "loss") {
              dropped += Number(frame.count) || 1;
              abort("Collector reported lost events");
            } else if (frame.type === "file-start") {
              if (
                files.size >= 16 ||
                typeof frame.id !== "string" ||
                files.has(frame.id)
              )
                throw new Error("Invalid artifact stream");
              const path = join(work, randomUUID());
              files.set(frame.id, {
                path,
                handle: await open(path, "wx", 0o600),
                name: String(frame.name).slice(0, 512),
                size: 0,
                mediaType: String(
                  frame.mediaType ?? "application/octet-stream",
                ),
                kind: String(frame.kind ?? "capture"),
              });
            } else if (frame.type === "file-data") {
              const file = files.get(frame.id);
              if (!file || typeof frame.data !== "string")
                throw new Error("Unknown artifact stream");
              const b = Buffer.from(frame.data, "base64");
              file.size += b.length;
              if (
                [...files.values()].reduce((n, f) => n + f.size, 0) +
                  evidence.bytes >
                evidence.budget
              )
                throw new Error("Evidence byte budget exhausted");
              await file.handle.write(b);
            } else if (frame.type === "file-end") {
              const file = files.get(frame.id);
              if (!file) throw new Error("Unknown artifact stream");
              await file.handle.close();
              files.delete(frame.id);
              await evidence.putFile(
                file.name,
                file.path,
                file.mediaType,
                file.kind,
              );
              await rm(file.path);
            } else if (frame.type === "complete") {
              if (files.size || !healthy || !traceEvents)
                throw new Error(
                  "Guest completed without complete telemetry and artifacts",
                );
              exitCode = Number.isInteger(frame.exitCode)
                ? frame.exitCode
                : null;
              finished = true;
              state = exitCode === 0 ? "completed" : "failed";
              resolveDone();
            } else if (frame.type === "error")
              abort(`Guest: ${String(frame.message)}`);
            if (evidence.needsFlush) queueFlush();
          })
          .catch((e) =>
            abort(
              String(e),
              String(e).includes("budget") ? "limit_reached" : "failed",
            ),
          )
          .finally(() => {
            queuedFrameBytes -= frameBytes;
            if (queuedFrameBytes < 512 * 1024) socket.resume();
          });
      });
    });
    await completion;
  } catch (e) {
    abort(e instanceof Error ? e.message : String(e));
  } finally {
    clearTimeout(startupTimer);
    clearTimeout(workloadTimer);
    clearTimeout(collectionTimer);
    clearInterval(interval);
    clearInterval(spaceTimer);
    options.signal?.removeEventListener("abort", cancel);
    stopping = true;
    if (channel) void channel.send({ type: "stop" }).catch(() => {});
    // Hard teardown is independent of guest cooperation.
    for (const child of [...children].reverse()) child.kill("SIGTERM");
    await sleep(500);
    for (const child of children)
      if (child.exitCode === null) child.kill("SIGKILL");
    channel?.stream.destroy();
    server.close();
    await frameChain;
    await flushChain;
    for (const f of files.values()) await f.handle.close().catch(() => {});
    try {
      await evidence.flush();
      for (const name of ["network.pcap", "http.mitm", "boot.log"]) {
        const p = join(work, name);
        try {
          await stat(p);
        } catch {
          continue;
        }
        await evidence.putFile(
          name,
          p,
          name.endsWith("pcap")
            ? "application/vnd.tcpdump.pcap"
            : "application/octet-stream",
          name.endsWith("pcap") ? "packets" : "diagnostic",
        );
      }
    } catch (e) {
      healthy = false;
      reason = [reason, String(e)].filter(Boolean).join("; ");
      if (String(state) === "completed") state = "limit_reached";
    }
    await rm(work, { recursive: true, force: true });
  }
  const manifest: EvidenceManifest = {
    version: 1,
    runId,
    attemptId,
    spec,
    startedAt,
    endedAt: new Date().toISOString(),
    state,
    exitCode,
    captureHealth:
      healthy && finished && !dropped && !reason ? "healthy" : "incomplete",
    reason,
    artifacts: evidence.artifacts,
    coverage: {
      enabled: healthy
        ? ["tracee", "file-capture", "processes", "packets", "gateway-policy"]
        : ["gateway-policy"],
      gaps: [
        ...knownGaps,
        "ICMP is recorded but not forwarded. DNS answers currently cover A/AAAA; other types return NODATA.",
      ],
      dropped,
    },
    provenance: runtime.provenance,
  };
  await writeFile(
    join(options.directory, "manifest.json"),
    JSON.stringify(manifest, null, 2),
    { mode: 0o600 },
  );
  return manifest;
}
