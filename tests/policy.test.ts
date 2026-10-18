import { test } from "node:test";
import assert from "node:assert/strict";
import {
  networkPolicy,
  runSpec,
  npmSpec,
} from "../packages/contracts/index.js";
import { Policy, isPublicIP, matches } from "../packages/core/policy.js";

test("public policy rejects protected IPv4, IPv6 and mapped destinations", () => {
  const p = new Policy(networkPolicy.parse({}), undefined, ["8.8.8.8"]);
  for (const ip of [
    "127.0.0.1",
    "10.3.1.2",
    "172.16.0.1",
    "192.168.1.1",
    "169.254.169.254",
    "100.100.100.200",
    "0.0.0.0",
    "224.0.0.1",
    "::1",
    "::ffff:127.0.0.1",
    "::ffff:8.8.8.8",
    "64:ff9b::a00:1",
    "fd00::1",
    "fe80::1",
    "2002:7f00:1::",
    "8.8.8.8",
  ])
    assert.equal(p.decide(ip, 443, "tcp").action, "deny", ip);
  assert.ok(isPublicIP("1.1.1.1"));
  assert.ok(isPublicIP("2606:4700:4700::1111"));
  assert.equal(p.decide("1.1.1.1", 80, "tcp").intercept, false);
  assert.equal(p.decide("1.1.1.1", 53, "udp").action, "deny");
});
test("allowlist tracks bounded DNS lifetimes but never overrides protected addresses", () => {
  const p = new Policy(
    networkPolicy.parse({
      mode: "allowlist",
      rules: [
        {
          id: "registry",
          host: "registry.npmjs.org",
          action: "allow",
          port: 443,
        },
      ],
    }),
  );
  assert.equal(p.decide("1.1.1.1", 443, "tcp").action, "deny");
  p.remember("registry.npmjs.org", ["1.1.1.1", "127.0.0.1"]);
  assert.equal(p.decide("1.1.1.1", 443, "tcp").action, "allow");
  assert.equal(p.decide("1.1.1.1", 80, "tcp").action, "deny");
  assert.equal(p.decide("127.0.0.1", 443, "tcp").action, "deny");
  p.remember("registry.npmjs.org", ["1.1.1.1"], -1);
  assert.equal(p.decide("1.1.1.1", 443, "tcp").action, "deny");
});
test("declarative HTTP mocks terminate locally and never authorize a private upstream", async () => {
  const p = new Policy(
    networkPolicy.parse({
      mode: "allowlist",
      rules: [
        {
          id: "fake",
          host: "test.example",
          action: "mock",
          response: { body: "test" },
        },
      ],
    }),
  );
  const answer = await p.dns("test.example.", 1);
  assert.deepEqual(answer.addresses, ["198.18.0.1"]);
  assert.equal(p.decide(answer.addresses[0]!, 443, "tcp").action, "mock");
  assert.equal(p.decide(answer.addresses[0]!, 443, "udp").action, "deny");
  assert.equal((await p.dns("other.example", 1)).rcode, 5);
  assert.equal(matches("*.example.com", "example.com"), false);
  assert.equal(matches("*.example.com", "a.example.com"), true);
});
test("specs reject host options, guest traversal and shell-shaped package names", () => {
  assert.throws(() =>
    runSpec.parse({ image: "image", argv: ["true"], privileged: true }),
  );
  assert.throws(() =>
    runSpec.parse({ image: "image", argv: ["true"], cwd: "/a/../b" }),
  );
  assert.throws(() => npmSpec("-g"));
  assert.throws(() => npmSpec("pkg@1; echo surprise"));
  assert.equal(
    npmSpec("@scope/package@1.2.3").argv.at(-1),
    "@scope/package@1.2.3",
  );
});
