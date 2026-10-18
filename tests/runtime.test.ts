import { test } from "node:test";
import assert from "node:assert/strict";
import { qemuArgs, type Runtime } from "../packages/core/runner.js";
import { runSpec } from "../packages/contracts/index.js";
test("QEMU has only the per-run network socket and no host filesystem shares", () => {
  const runtime = {
    qemu: "qemu-system-x86_64",
    acceleration: "kvm",
    architecture: "x64",
    image: "/base",
    kernel: "/kernel",
    initrd: "/initrd",
  } as Runtime;
  const args = qemuArgs(
    runtime,
    runSpec.parse({ image: "base", argv: ["true"] }),
    "/tmp/job",
  );
  assert.ok(args.includes("-nodefaults"));
  assert.ok(args.includes("-sandbox"));
  assert.ok(args.includes("kvm"));
  assert.equal(args.filter((a) => a === "-netdev").length, 1);
  assert.ok(args.some((a) => a.includes("/tmp/job/network.sock")));
  assert.ok(
    !args.some((a) => /hostfwd|virtfs|fsdev|accel=tcg|type=user/.test(a)),
  );
});
