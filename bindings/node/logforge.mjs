// Node binding: the same C core, compiled to WebAssembly. No native addon, no dependencies.
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";

const here = dirname(fileURLToPath(import.meta.url));
const wasmPath = process.env.LOGFORGE_WASM ?? join(here, "..", "..", "build", "logforge.wasm");

let compiled;
function module() {
  compiled ??= new WebAssembly.Module(readFileSync(wasmPath));
  return compiled;
}

export class LogForge {
  #x;
  #inPtr;
  #inCap;
  #outPtr;

  constructor() {
    // Every instance owns its linear memory, so instances are fully independent.
    this.#x = new WebAssembly.Instance(module(), {}).exports;
    this.#inPtr = this.#x.lf_in_ptr();
    this.#inCap = this.#x.lf_in_cap();
    this.#outPtr = this.#x.lf_out_ptr();
    this.#x.lf_reset();
  }

  /** Feed a Buffer or Uint8Array in any chunking; lines may span calls. */
  feed(data) {
    const bytes = data instanceof Uint8Array ? data : Buffer.from(data);
    for (let off = 0; off < bytes.length; off += this.#inCap) {
      const part = bytes.subarray(off, off + this.#inCap);
      new Uint8Array(this.#x.memory.buffer, this.#inPtr, part.length).set(part);
      this.#x.lf_feed_in(part.length);
    }
  }

  analyzeFile(path, chunk = 1 << 20) {
    const fd = openSync(path, "r");
    try {
      const buf = Buffer.allocUnsafe(Math.min(chunk, this.#inCap));
      for (let n; (n = readSync(fd, buf, 0, buf.length, null)) > 0; ) this.feed(buf.subarray(0, n));
    } finally {
      closeSync(fd);
    }
  }

  /** Flushes a final line without newline and returns the report object. */
  report() {
    const n = this.#x.lf_finish();
    if (n === 0) throw new Error("report buffer too small");
    const raw = new Uint8Array(this.#x.memory.buffer, this.#outPtr, n);
    return JSON.parse(Buffer.from(raw).toString("latin1"));
  }

  /** Raw JSON text, byte-identical to the C CLI output. */
  reportJSON() {
    const n = this.#x.lf_finish();
    if (n === 0) throw new Error("report buffer too small");
    return Buffer.from(new Uint8Array(this.#x.memory.buffer, this.#outPtr, n)).toString("latin1");
  }

  reset() {
    this.#x.lf_reset();
  }
}

import { openSync, readSync, closeSync } from "node:fs";
