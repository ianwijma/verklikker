import { createHash } from "node:crypto";
import { createReadStream } from "node:fs";
import { writeFile } from "node:fs/promises";
const architecture = process.argv[2],
  sha256 = {};
for (const [key, name] of Object.entries({
  image: "rootfs.qcow2",
  kernel: "vmlinuz",
  initrd: "initrd",
})) {
  const hash = createHash("sha256");
  for await (const b of createReadStream(`runtime/${architecture}/${name}`))
    hash.update(b);
  sha256[key] = hash.digest("hex");
}
await writeFile(
  `runtime/${architecture}/manifest.json`,
  JSON.stringify(
    {
      version: 1,
      architecture,
      traceeImage: process.argv[3],
      builtAt: new Date().toISOString(),
      sha256,
    },
    null,
    2,
  ),
);
