import { LogForge } from "./logforge.mjs";

const files = process.argv.slice(2);
if (files.length === 0) {
  console.error("usage: node cli.mjs access.log [more.log ...]");
  process.exit(2);
}
const lf = new LogForge();
for (const f of files) lf.analyzeFile(f);
console.log(lf.reportJSON());
