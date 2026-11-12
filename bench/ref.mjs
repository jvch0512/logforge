// Pure-JavaScript reference implementation with exactly the same semantics as the C core.
import { readFileSync } from "node:fs";

const MAX_LINE = 8192, DEC_MAX = 2047, UA_MAX = 511, TOP_N = 5, BRUTE_MIN = 10;
const IP_MAX_LOAD = 90000, PATH_MAX_LOAD = 45000, PATH_KEY = 96;
const RULES = ["sqli", "traversal", "xss", "scanner", "shellshock", "log4shell", "sensitive_file"];
const SQLI = ["union select", "or 1=1", "' or '", "sleep(", "information_schema", "benchmark(", "; drop "];
const TRAV = ["../", "..\\", "/etc/passwd", "boot.ini"];
const XSS = ["<script", "onerror=", "onload=", "javascript:", "<svg"];
const SCAN = ["sqlmap", "nikto", "nmap", "masscan", "gobuster", "dirbuster", "wpscan", "nuclei", "zgrab"];
const SENS = [".env", ".git/", "wp-config", ".aws/credentials", "id_rsa", "phpinfo", ".htpasswd", "/server-status"];
const MONTHS = ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"];
const DIM = [31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31];

const Q = '((?:[^"\\\\]|\\\\.)*)';
const LINE = new RegExp(
  "^([0-9a-fA-F:.]{1,45}) [^ ]+ [^ ]+ \\[(\\d\\d)/([A-Za-z]{3})/(\\d{4}):(\\d\\d):(\\d\\d):(\\d\\d) ([+-])(\\d\\d)(\\d\\d)\\]" +
    ' "' + Q + '" (\\d{3}) (\\d{1,18}|-)(?: "' + Q + '" "' + Q + '")?$',
  "s",
);
const PCT = /%([0-9a-fA-F]{2})|\+/g;

const lowerAscii = (s) => s.replace(/[A-Z]+/g, (m) => m.toLowerCase());

function daysFromCivil(y, m, d) {
  y -= m <= 2 ? 1 : 0;
  const era = Math.floor((y >= 0 ? y : y - 399) / 400);
  const yoe = y - era * 400;
  const doy = Math.floor((153 * (m + (m > 2 ? -3 : 9)) + 2) / 5) + d - 1;
  const doe = yoe * 365 + Math.floor(yoe / 4) - Math.floor(yoe / 100) + doy;
  return era * 146097 + doe - 719468;
}

function parse(line) {
  const m = LINE.exec(line);
  if (!m) return null;
  const [, ip, d0, mon, y0, hh0, mm0, ss0, sign, th0, tm0, req, st0, nb, ref, ua] = m;
  const d = +d0, y = +y0, hh = +hh0, mm = +mm0, ss = +ss0, th = +th0, tm = +tm0, status = +st0;
  const mo = MONTHS.indexOf(mon) + 1;
  if (!mo) return null;
  const leap = (y % 4 === 0 && y % 100 !== 0) || y % 400 === 0;
  if (d < 1 || y < 1970 || y > 2100 || hh > 23 || mm > 59 || ss > 60 || th > 23 || tm > 59 || d > DIM[mo - 1] + (mo === 2 && leap ? 1 : 0)) return null;
  if (status < 100 || status > 599) return null;
  const t = daysFromCivil(y, mo, d) * 86400 + hh * 3600 + mm * 60 + ss;
  const off = th * 3600 + tm * 60;
  const sp = req.indexOf(" ");
  const path = sp < 0 ? "" : req.slice(sp + 1).split(" ")[0];
  return { ip, path, status, bytes: nb === "-" ? 0 : Number(nb), ts: sign === "+" ? t - off : t + off, ref: ref ?? "", ua: ua ?? "" };
}

function detect(path, ua, ref) {
  const dec = lowerAscii(path.replace(PCT, (s, h) => (s === "+" ? " " : String.fromCharCode(parseInt(h, 16))))).slice(0, DEC_MAX);
  const u = lowerAscii(ua).slice(0, UA_MAX);
  const r = lowerAscii(ref).slice(0, UA_MAX);
  const q = dec.indexOf("?");
  const base = q < 0 ? dec : dec.slice(0, q);
  return [
    SQLI.some((n) => dec.includes(n)),
    TRAV.some((n) => dec.includes(n)),
    XSS.some((n) => dec.includes(n)),
    SCAN.some((n) => u.includes(n)),
    dec.includes("() {") || u.includes("() {") || r.includes("() {"),
    dec.includes("${jndi:") || u.includes("${jndi:") || r.includes("${jndi:"),
    SENS.some((n) => base.includes(n)),
  ];
}

function jstr(s) {
  let o = '"';
  for (let i = 0; i < s.length; i++) {
    const c = s.charCodeAt(i);
    o += c < 0x20 || c === 0x22 || c === 0x5c || c >= 0x7f ? "\\u" + c.toString(16).padStart(4, "0") : s[i];
  }
  return o + '"';
}

const cmp = (a, b) => (a < b ? -1 : a > b ? 1 : 0); // latin1 strings: code unit order equals byte order

function top(entries, min) {
  return entries.filter(([, v]) => v >= min).sort((a, b) => b[1] - a[1] || cmp(a[0], b[0])).slice(0, TOP_N);
}

export function analyze(paths) {
  let lines = 0, parsed = 0, malformed = 0, nbytes = 0, attackLines = 0, first = null, last = null, ipOver = 0, pathOver = 0;
  const status = [0, 0, 0, 0, 0], rules = [0, 0, 0, 0, 0, 0, 0];
  const ips = new Map(), pathsT = new Map();
  for (const p of paths) {
    for (const raw of readFileSync(p).toString("latin1").split("\n")) {
      if (raw === "") continue;
      if (raw.length > MAX_LINE) { lines++; malformed++; continue; }
      const line = raw.endsWith("\r") ? raw.slice(0, -1) : raw;
      if (line === "") continue;
      lines++;
      const e = parse(line);
      if (!e) { malformed++; continue; }
      parsed++;
      nbytes += e.bytes;
      status[Math.floor(e.status / 100) - 1]++;
      if (first === null || e.ts < first) first = e.ts;
      if (last === null || e.ts > last) last = e.ts;
      const hit = detect(e.path, e.ua, e.ref);
      hit.forEach((h, i) => { if (h) rules[i]++; });
      const any = hit.some(Boolean);
      if (any) attackLines++;
      let slot = ips.get(e.ip);
      if (!slot && ips.size >= IP_MAX_LOAD) ipOver++;
      else {
        if (!slot) ips.set(e.ip, (slot = [0, 0, 0]));
        slot[0]++;
        if (any) slot[1]++;
        if (e.status === 401) slot[2]++;
      }
      const qi = e.path.indexOf("?");
      const key = (qi < 0 ? e.path : e.path.slice(0, qi)).slice(0, PATH_KEY - 1);
      if (key) {
        if (!pathsT.has(key) && pathsT.size >= PATH_MAX_LOAD) pathOver++;
        else pathsT.set(key, (pathsT.get(key) ?? 0) + 1);
      }
    }
  }
  const arr = (name, label, rows) => `,"${name}":[${rows.map(([k, v]) => `{"${label}":${jstr(k)},"count":${v}}`).join(",")}]`;
  const ipRows = (i) => [...ips].map(([k, v]) => [k, v[i]]);
  let s = `{"lines":${lines},"parsed":${parsed},"malformed":${malformed},"bytes":${nbytes},"first_ts":${first ?? 0},"last_ts":${last ?? 0}`;
  s += `,"status":{${status.map((v, i) => `"${i + 1}xx":${v}`).join(",")}}`;
  s += `,"unique_ips":${ips.size},"ip_overflow":${ipOver},"unique_paths":${pathsT.size},"path_overflow":${pathOver},"attack_lines":${attackLines}`;
  s += `,"attacks":{${RULES.map((n, i) => `"${n}":${rules[i]}`).join(",")}}`;
  s += arr("top_ips", "ip", top(ipRows(0), 1));
  s += arr("attackers", "ip", top(ipRows(1), 1));
  s += arr("auth_failures", "ip", top(ipRows(2), BRUTE_MIN));
  s += arr("top_paths", "path", top([...pathsT], 1));
  return s + "}";
}

if (import.meta.url === `file://${process.argv[1]}`) {
  if (process.argv.length < 3) { console.error("usage: node ref.mjs access.log [more.log ...]"); process.exit(2); }
  console.log(analyze(process.argv.slice(2)));
}
