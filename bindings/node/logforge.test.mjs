import test from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";
import { execFileSync } from "node:child_process";
import { LogForge } from "./logforge.mjs";

const root = join(dirname(fileURLToPath(import.meta.url)), "..", "..");
const fixture = join(root, "fixtures", "sample.log");

test("fixture report", () => {
  const lf = new LogForge();
  lf.analyzeFile(fixture);
  const r = lf.report();
  assert.deepEqual([r.lines, r.parsed, r.malformed, r.bytes], [32, 29, 3, 23340]);
  assert.deepEqual(r.status, { "1xx": 0, "2xx": 11, "3xx": 1, "4xx": 16, "5xx": 1 });
  assert.deepEqual(r.attacks, { sqli: 1, traversal: 1, xss: 2, scanner: 3, shellshock: 1, log4shell: 1, sensitive_file: 2 });
  assert.deepEqual(r.top_ips[0], { ip: "192.0.2.55", count: 12 });
  assert.equal(r.attack_lines, 8);
});

test("output is byte-identical to the native CLI", () => {
  const lf = new LogForge();
  lf.analyzeFile(fixture);
  const native = execFileSync(join(root, "build", "logforge"), ["--json", fixture]).toString().trim();
  assert.equal(lf.reportJSON(), native);
});

test("chunking does not change the result", () => {
  const data = readFileSync(fixture);
  const whole = new LogForge();
  whole.feed(data);
  const expected = whole.reportJSON();
  for (const step of [1, 7, 64, 1000]) {
    const lf = new LogForge();
    for (let i = 0; i < data.length; i += step) lf.feed(data.subarray(i, i + step));
    assert.equal(lf.reportJSON(), expected, `step ${step}`);
  }
});

test("input larger than the WASM input buffer is split transparently", () => {
  const line = '192.0.2.1 - - [10/Oct/2026:13:55:36 +0000] "GET /x HTTP/1.1" 200 1 "-" "x"\n';
  const lf = new LogForge();
  const big = Buffer.from(line.repeat(40000)); // about 3 MB, the wasm buffer is 1 MiB
  lf.feed(big);
  assert.equal(lf.report().parsed, 40000);
});

test("instances are independent and reset works", () => {
  const a = new LogForge();
  const b = new LogForge();
  a.feed(readFileSync(fixture));
  assert.equal(b.report().lines, 0);
  assert.equal(a.report().lines, 32);
  a.reset();
  assert.equal(a.report().lines, 0);
});

test("hostile bytes produce valid JSON", () => {
  const lf = new LogForge();
  lf.feed(Buffer.from('192.0.2.1 - - [10/Oct/2026:13:55:36 +0000] "GET /\xff\xfe\\"\x01 HTTP/1.1" 200 1 "-" "x"\n', "latin1"));
  lf.feed(Buffer.from(Array.from({ length: 5120 }, (_, i) => i % 256)));
  const r = lf.report();
  assert.equal(r.parsed, 1);
  assert.equal(r.top_paths[0].path, "/ÿþ\\\"\u0001");
});

test("a last line without newline is counted", () => {
  const lf = new LogForge();
  lf.feed(Buffer.from('192.0.2.1 - - [10/Oct/2026:13:55:36 +0000] "GET / HTTP/1.1" 200 1 "-" "x"'));
  assert.equal(lf.report().parsed, 1);
});
