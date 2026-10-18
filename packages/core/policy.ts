import { BlockList, isIP } from "node:net";
import { networkInterfaces } from "node:os";
import { resolve4, resolve6 } from "node:dns/promises";
import type { NetworkPolicy } from "../contracts/index.js";

const denied = new BlockList();
const denied6 = new BlockList();
for (const [address, prefix] of [
  ["0.0.0.0", 8],
  ["10.0.0.0", 8],
  ["100.64.0.0", 10],
  ["127.0.0.0", 8],
  ["169.254.0.0", 16],
  ["172.16.0.0", 12],
  ["192.0.0.0", 24],
  ["192.0.2.0", 24],
  ["192.168.0.0", 16],
  ["198.18.0.0", 15],
  ["198.51.100.0", 24],
  ["203.0.113.0", 24],
  ["224.0.0.0", 4],
  ["240.0.0.0", 4],
] as const)
  denied.addSubnet(address, prefix);
for (const [address, prefix] of [
  ["::", 96],
  ["::ffff:0:0", 96],
  ["64:ff9b::", 96],
  ["100::", 64],
  ["2001::", 32],
  ["2001:db8::", 32],
  ["2002::", 16],
  ["fc00::", 7],
  ["fe80::", 10],
  ["ff00::", 8],
] as const)
  denied6.addSubnet(address, prefix, "ipv6");
const global6 = new BlockList();
global6.addSubnet("2000::", 3, "ipv6");
export function isPublicIP(ip: string): boolean {
  const family = isIP(ip);
  return family === 4
    ? !denied.check(ip)
    : family === 6 && global6.check(ip, "ipv6") && !denied6.check(ip, "ipv6");
}
export function matches(pattern: string, name: string): boolean {
  pattern = pattern.toLowerCase().replace(/\.$/, "");
  name = name.toLowerCase().replace(/\.$/, "");
  return pattern.startsWith("*.")
    ? name.endsWith(pattern.slice(1)) && name !== pattern.slice(2)
    : pattern === name;
}
export interface Decision {
  action: "allow" | "deny" | "mock";
  reason: string;
  host?: string;
  rule?: string;
  intercept?: boolean;
  response?: { status: number; headers: Record<string, string>; body: string };
}
export class Policy {
  private names = new Map<string, Map<string, number>>();
  private blocked = new BlockList();
  constructor(
    readonly config: NetworkPolicy,
    private emit: (data: Record<string, unknown>) => void = () => {},
    protectedIPs: string[] = [],
    private protectedHosts: string[] = [],
  ) {
    for (const a of Object.values(networkInterfaces()).flat())
      if (a)
        this.blocked.addAddress(
          a.address,
          isIP(a.address) === 6 ? "ipv6" : "ipv4",
        );
    protectedIPs.forEach((a) =>
      this.blocked.addAddress(a, isIP(a) === 6 ? "ipv6" : "ipv4"),
    );
  }
  remember(name: string, addresses: string[], ttl = 60) {
    if (this.names.size > 8192)
      for (const [ip, names] of this.names) {
        for (const [n, until] of names)
          if (until <= Date.now()) names.delete(n);
        if (!names.size) this.names.delete(ip);
      }
    if (this.names.size > 16384)
      throw new Error("DNS tracking budget exhausted");
    for (const ip of addresses) {
      const map = this.names.get(ip) ?? new Map();
      if (map.size >= 256) map.delete(map.keys().next().value!);
      map.set(name, Date.now() + ttl * 1000);
      this.names.set(ip, map);
    }
  }
  async dns(
    name: string,
    type: number,
  ): Promise<{ addresses: string[]; rcode: number }> {
    name = name.toLowerCase().replace(/\.$/, "");
    const rule = this.config.rules.find((r) => matches(r.host, name));
    let addresses: string[] = [];
    let rcode = 0;
    const mock = this.config.dns.find((d) => matches(d.host, name));
    if (
      this.protectedHosts.includes(name) ||
      rule?.action === "deny" ||
      (this.config.mode === "allowlist" && !rule && !mock)
    )
      rcode = 5;
    else if (rule?.action === "mock") addresses = ["198.18.0.1"];
    else if (mock) addresses = mock.addresses;
    else if (isIP(name)) addresses = [name];
    else if (type === 1 || type === 28) {
      try {
        addresses = await (type === 1 ? resolve4(name) : resolve6(name));
      } catch {
        rcode = 3;
      }
    }
    addresses = addresses.filter((ip) => isIP(ip) === (type === 28 ? 6 : 4));
    this.remember(name, addresses);
    this.emit({
      kind: "dns",
      host: name,
      type,
      addresses,
      rcode,
      mocked: !!mock || rule?.action === "mock",
    });
    return { addresses, rcode };
  }
  decide(
    ip: string,
    port: number,
    protocol: "tcp" | "udp",
    explicitHost?: string,
  ): Decision {
    const names = explicitHost
      ? [explicitHost.toLowerCase().replace(/\.$/, "")]
      : [...(this.names.get(ip) ?? [])]
          .filter(([, expires]) => expires > Date.now())
          .map(([name]) => name);
    const rule = this.config.rules.find(
      (r) =>
        (r.port === undefined || r.port === port) &&
        (r.protocol === "any" || r.protocol === protocol) &&
        [ip, ...names].some((n) => matches(r.host, n)),
    );
    let result: Decision;
    if (rule?.action === "mock" && protocol === "tcp")
      result = {
        action: "mock",
        reason: "mock rule",
        rule: rule.id,
        host: names[0] ?? ip,
        response: rule.response,
        intercept: true,
      };
    else if (
      names.some((n) => this.protectedHosts.includes(n)) ||
      !isPublicIP(ip) ||
      this.blocked.check(ip, isIP(ip) === 6 ? "ipv6" : "ipv4")
    )
      result = { action: "deny", reason: "protected destination" };
    else if (port === 53 || port === 853)
      result = { action: "deny", reason: "use the recorded gateway resolver" };
    else if (rule?.action === "deny")
      result = { action: "deny", reason: "deny rule", rule: rule.id };
    else if (this.config.mode === "allowlist" && rule?.action !== "allow")
      result = { action: "deny", reason: "not allowlisted" };
    else
      result = {
        action: "allow",
        reason: rule ? "allow rule" : "public internet",
        rule: rule?.id,
        host: names[0] ?? ip,
        intercept:
          protocol === "tcp" &&
          this.config.tls === "intercept" &&
          (port === 80 || port === 443),
      };
    this.emit({ kind: "network.policy", ip, port, protocol, ...result });
    return result;
  }
}
