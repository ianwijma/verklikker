import { z } from "zod";

export const GiB = 1024 ** 3;
const safePath = z
  .string()
  .min(1)
  .max(4096)
  .refine(
    (p) =>
      p.startsWith("/") && !p.split("/").includes("..") && !p.includes("\0"),
    "Use an absolute guest path without .. or NUL",
  );
const host = z
  .string()
  .min(1)
  .max(253)
  .regex(/^(\*\.)?[a-zA-Z0-9._:-]+$/);
export const networkRule = z
  .object({
    id: z.string().regex(/^[a-zA-Z0-9_-]{1,64}$/),
    host,
    port: z.number().int().min(1).max(65535).optional(),
    protocol: z.enum(["tcp", "udp", "any"]).default("any"),
    action: z.enum(["allow", "deny", "mock"]),
    response: z
      .object({
        status: z.number().int().min(100).max(599).default(200),
        headers: z.record(z.string(), z.string()).default({}),
        body: z
          .string()
          .max(1024 * 1024)
          .default(""),
      })
      .strict()
      .optional(),
  })
  .strict()
  .superRefine((r, c) => {
    if (r.action === "mock" && !r.response)
      c.addIssue({ code: "custom", message: "HTTP mock requires response" });
  });
export const networkPolicy = z
  .object({
    mode: z.enum(["public", "allowlist"]).default("public"),
    tls: z.enum(["passthrough", "intercept"]).default("passthrough"),
    rules: z.array(networkRule).max(256).default([]),
    dns: z
      .array(
        z
          .object({
            host,
            addresses: z.array(z.union([z.ipv4(), z.ipv6()])).max(16),
          })
          .strict(),
      )
      .max(128)
      .default([]),
    bytes: z
      .number()
      .int()
      .positive()
      .max(100 * GiB)
      .default(GiB),
    bytesPerSecond: z
      .number()
      .int()
      .positive()
      .max(GiB)
      .default(2 * 1024 * 1024),
    connections: z.number().int().positive().max(4096).default(128),
  })
  .strict();
export const runSpec = z
  .object({
    version: z.literal(1).default(1),
    label: z.string().max(200).default("Investigation"),
    image: z
      .string()
      .min(1)
      .max(512)
      .regex(/^[a-zA-Z0-9][a-zA-Z0-9._:/@-]*$/),
    argv: z
      .array(
        z
          .string()
          .max(65536)
          .refine((s) => !s.includes("\0")),
      )
      .min(1)
      .max(256),
    env: z
      .record(
        z.string().regex(/^[a-zA-Z_][a-zA-Z0-9_]*$/),
        z.string().max(65536),
      )
      .default({}),
    cwd: safePath.default("/work"),
    user: z
      .string()
      .regex(/^\d+(:\d+)?$/)
      .default("1000:1000"),
    architecture: z.enum(["x64", "arm64"]).optional(),
    inputs: z
      .array(
        z
          .object({
            artifactId: z.uuid(),
            path: safePath,
            executable: z.boolean().default(false),
          })
          .strict(),
      )
      .max(100)
      .default([]),
    limits: z
      .object({
        cpus: z.number().int().min(1).max(32).default(2),
        memoryMiB: z.number().int().min(1024).max(65536).default(4096),
        timeoutSeconds: z.number().int().min(1).max(86400).default(600),
        observeSeconds: z.number().int().min(0).max(3600).default(5),
        diskBytes: z
          .number()
          .int()
          .min(GiB)
          .max(200 * GiB)
          .default(20 * GiB),
        evidenceBytes: z
          .number()
          .int()
          .min(1024 * 1024)
          .max(100 * GiB)
          .default(10 * GiB),
        pids: z.number().int().min(16).max(4096).default(512),
      })
      .strict()
      .prefault({}),
    network: networkPolicy.prefault({}),
  })
  .strict();
export type RunSpec = z.infer<typeof runSpec>;
export type NetworkPolicy = z.infer<typeof networkPolicy>;
export const workerCapacity = z
  .object({
    cpus: z.number().int().min(1).max(32).default(2),
    memoryMiB: z.number().int().min(1024).max(65536).default(4096),
    diskBytes: z
      .number()
      .int()
      .positive()
      .default(20 * GiB),
    evidenceBytes: z
      .number()
      .int()
      .positive()
      .default(10 * GiB),
  })
  .strict()
  .prefault({});
export type WorkerCapacity = z.infer<typeof workerCapacity>;
export const terminalStates = [
  "completed",
  "failed",
  "cancelled",
  "interrupted",
  "timed_out",
  "limit_reached",
] as const;
export type RunState =
  | "queued"
  | "booting"
  | "running"
  | "collecting"
  | (typeof terminalStates)[number];
export type CaptureHealth = "pending" | "healthy" | "incomplete";
export interface EvidenceEvent {
  version: 1;
  runId: string;
  attemptId: string;
  source: string;
  sequence: number;
  timestamp: string;
  receivedAt: string;
  kind: string;
  processId?: string;
  parentId?: string;
  data: Record<string, unknown>;
  rawRef?: string;
}
export interface Artifact {
  id: string;
  name: string;
  size: number;
  sha256: string;
  mediaType: string;
  kind: string;
}
export interface EvidenceManifest {
  version: 1;
  runId: string;
  attemptId: string;
  spec: RunSpec;
  startedAt: string;
  endedAt: string;
  state: RunState;
  exitCode: number | null;
  captureHealth: CaptureHealth;
  reason?: string;
  artifacts: Artifact[];
  coverage: { enabled: string[]; gaps: string[]; dropped: number };
  provenance: Record<string, unknown>;
}
export const knownGaps = [
  "Memory-mapped accesses are represented by mappings and final filesystem state, not every memory read or write.",
  "File content captures may be partial or overwritten; they are not a complete history of file versions.",
  "TLS passthrough, certificate pinning and unsupported encrypted protocols prevent plaintext inspection.",
  "Guest kernel compromise can invalidate guest telemetry; external packet evidence is independent.",
  "Raw collector argument buffers may be bounded; unknown collector fields remain in raw records.",
];
export const submission = z
  .object({ spec: runSpec, idempotencyKey: z.string().max(128).optional() })
  .strict();
export function npmSpec(packageSpec: string): RunSpec {
  if (
    !/^(?:@[a-zA-Z0-9_.-]+\/)?[a-zA-Z0-9_.-]+(?:@[^\s;`$\\]+)?$/.test(
      packageSpec,
    ) ||
    packageSpec.startsWith("-")
  )
    throw new Error(
      "Use an npm registry package name with an optional version",
    );
  return runSpec.parse({
    image: "verklikker/npm:local",
    label: packageSpec,
    argv: [
      "npm",
      "install",
      "--foreground-scripts",
      "--no-audit",
      "--no-fund",
      "--",
      packageSpec,
    ],
  });
}
