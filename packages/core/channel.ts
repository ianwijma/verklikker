import { EventEmitter } from "node:events";
import type { Duplex } from "node:stream";
/** Length-bounded JSON lines. Guest filenames are never interpreted as host paths. */
export class Channel extends EventEmitter {
  private buffer = Buffer.alloc(0);
  constructor(
    readonly stream: Duplex,
    readonly limit = 1024 * 1024,
  ) {
    super();
    stream.on("data", (part: Buffer) => {
      this.buffer = Buffer.concat([this.buffer, part]);
      for (;;) {
        const end = this.buffer.indexOf(10);
        if (end < 0) break;
        if (end > limit) {
          stream.destroy(new Error("Guest frame exceeded limit"));
          return;
        }
        const line = this.buffer.subarray(0, end);
        this.buffer = this.buffer.subarray(end + 1);
        try {
          const frame = JSON.parse(line.toString());
          this.emit("frame", frame);
        } catch {
          stream.destroy(new Error("Invalid guest frame"));
          return;
        }
      }
      if (this.buffer.length > limit)
        stream.destroy(new Error("Guest frame exceeded limit"));
    });
    stream.on("error", (e) => this.emit("failure", e));
    stream.on("close", () => this.emit("closed"));
  }
  async send(frame: unknown) {
    const body = JSON.stringify(frame) + "\n";
    if (Buffer.byteLength(body) > this.limit)
      throw new Error("Frame exceeded limit");
    if (this.stream.destroyed) throw new Error("Channel closed");
    await new Promise<void>((ok, fail) => {
      const closed = () => {
        cleanup();
        fail(new Error("Channel closed during write"));
      };
      const cleanup = () => this.stream.off("close", closed);
      this.stream.once("close", closed);
      this.stream.write(body, (e) => {
        cleanup();
        if (e) fail(e);
        else ok();
      });
    });
  }
}
