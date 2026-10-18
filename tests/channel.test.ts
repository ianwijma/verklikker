import { test } from "node:test";
import assert from "node:assert/strict";
import { Duplex, PassThrough } from "node:stream";
import { once } from "node:events";
import { Channel } from "../packages/core/channel.js";
test("channel reassembles split frames and rejects oversized guest input", async () => {
  const stream = new PassThrough();
  const c = new Channel(stream, 32);
  const frame = once(c, "frame");
  stream.write('{"type":');
  stream.write('"ready"}\n');
  assert.deepEqual((await frame)[0], { type: "ready" });
  const fail = once(c, "failure");
  stream.write("x".repeat(33));
  assert.match(String((await fail)[0]), /exceeded/);
});
test("blocked writes reject when the transport disappears", async () => {
  const stream = new Duplex({
    read() {},
    write(_chunk, _encoding, _callback) {},
  });
  const c = new Channel(stream);
  const sent = c.send({ type: "test" });
  stream.destroy();
  await assert.rejects(sent, /closed/);
});
