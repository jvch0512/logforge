"""Pure-Python reference implementation with exactly the same semantics as the C core.

It exists for two reasons: a baseline for the benchmark, and an independent second
implementation, so the conformance test can prove the C core and both bindings agree with it
byte for byte."""
import re
import sys

MAX_LINE, DEC_MAX, UA_MAX, TOP_N, BRUTE_MIN = 8192, 2047, 511, 5, 10
IP_MAX_LOAD, PATH_MAX_LOAD, PATH_KEY = 90000, 45000, 96
RULES = ["sqli", "traversal", "xss", "scanner", "shellshock", "log4shell", "sensitive_file"]
SQLI = [b"union select", b"or 1=1", b"' or '", b"sleep(", b"information_schema", b"benchmark(", b"; drop "]
TRAV = [b"../", b"..\\", b"/etc/passwd", b"boot.ini"]
XSS = [b"<script", b"onerror=", b"onload=", b"javascript:", b"<svg"]
SCAN = [b"sqlmap", b"nikto", b"nmap", b"masscan", b"gobuster", b"dirbuster", b"wpscan", b"nuclei", b"zgrab"]
SENS = [b".env", b".git/", b"wp-config", b".aws/credentials", b"id_rsa", b"phpinfo", b".htpasswd", b"/server-status"]
MONTHS = [b"Jan", b"Feb", b"Mar", b"Apr", b"May", b"Jun", b"Jul", b"Aug", b"Sep", b"Oct", b"Nov", b"Dec"]
DIM = [31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31]

Q = rb'((?:[^"\\]|\\.)*)'
LINE = re.compile(
    rb"([0-9a-fA-F:.]{1,45}) [^ ]+ [^ ]+ \[(\d\d)/([A-Za-z]{3})/(\d{4}):(\d\d):(\d\d):(\d\d) ([+-])(\d\d)(\d\d)\]"
    rb' "' + Q + rb'" (\d{3}) (\d{1,18}|-)(?: "' + Q + rb'" "' + Q + rb'")?',
    re.DOTALL,
)
PCT = re.compile(rb"%([0-9a-fA-F]{2})|\+")


def days_from_civil(y, m, d):
    y -= m <= 2
    era = (y if y >= 0 else y - 399) // 400
    yoe = y - era * 400
    doy = (153 * (m + (-3 if m > 2 else 9)) + 2) // 5 + d - 1
    doe = yoe * 365 + yoe // 4 - yoe // 100 + doy
    return era * 146097 + doe - 719468


def parse(line):
    m = LINE.fullmatch(line)
    if not m:
        return None
    ip, d, mon, y, hh, mm, ss, sign, th, tm, req, status, nbytes, ref, ua = m.groups()
    d, y, hh, mm, ss, th, tm, status = int(d), int(y), int(hh), int(mm), int(ss), int(th), int(tm), int(status)
    if mon not in MONTHS:
        return None
    mo = MONTHS.index(mon) + 1
    leap = (y % 4 == 0 and y % 100 != 0) or y % 400 == 0
    if d < 1 or y < 1970 or y > 2100 or hh > 23 or mm > 59 or ss > 60 or th > 23 or tm > 59 or d > DIM[mo - 1] + (mo == 2 and leap):
        return None
    if not 100 <= status <= 599:
        return None
    t = days_from_civil(y, mo, d) * 86400 + hh * 3600 + mm * 60 + ss
    off = th * 3600 + tm * 60
    ts = t - off if sign == b"+" else t + off
    method, _, rest = req.partition(b" ")
    path = rest.split(b" ", 1)[0] if _ else b""
    return ip, path, status, 0 if nbytes == b"-" else int(nbytes), ts, ref or b"", ua or b""


def _dec(m):
    return b" " if m.group(0) == b"+" else bytes([int(m.group(1), 16)])


def detect(path, ua, ref):
    dec = PCT.sub(_dec, path).lower()[:DEC_MAX]
    ua = ua.lower()[:UA_MAX]
    ref = ref.lower()[:UA_MAX]
    hit = [
        any(n in dec for n in SQLI),
        any(n in dec for n in TRAV),
        any(n in dec for n in XSS),
        any(n in ua for n in SCAN),
        b"() {" in dec or b"() {" in ua or b"() {" in ref,
        b"${jndi:" in dec or b"${jndi:" in ua or b"${jndi:" in ref,
        any(n in dec.split(b"?", 1)[0] for n in SENS),
    ]
    return hit


def jstr(b):
    out = ['"']
    for c in b:
        if c < 0x20 or c in (0x22, 0x5C) or c >= 0x7F:
            out.append("\\u%04x" % c)
        else:
            out.append(chr(c))
    out.append('"')
    return "".join(out)


def top(items, minimum):
    rows = [(k, v) for k, v in items if v >= minimum]
    rows.sort(key=lambda kv: (-kv[1], kv[0]))
    return rows[:TOP_N]


def analyze(paths):
    lines = parsed = malformed = nbytes = attack_lines = 0
    status = [0] * 5
    rules = [0] * 7
    first = last = None
    ips, ip_over, paths_t, path_over = {}, 0, {}, 0
    data = b"".join(open(p, "rb").read() for p in paths) if False else None
    for p in paths:
        with open(p, "rb") as f:
            data = f.read()
        for raw in data.split(b"\n"):
            if not raw:
                continue
            if len(raw) > MAX_LINE:
                lines += 1
                malformed += 1
                continue
            line = raw[:-1] if raw.endswith(b"\r") else raw
            if not line:
                continue
            lines += 1
            e = parse(line)
            if e is None:
                malformed += 1
                continue
            parsed += 1
            ip, path, st, nb, ts, ref, ua = e
            nbytes += nb
            status[st // 100 - 1] += 1
            first = ts if first is None or ts < first else first
            last = ts if last is None or ts > last else last
            hit = detect(path, ua, ref)
            for i, h in enumerate(hit):
                rules[i] += h
            any_hit = any(hit)
            attack_lines += any_hit
            slot = ips.get(ip)
            if slot is None and len(ips) >= IP_MAX_LOAD:
                ip_over += 1
            else:
                if slot is None:
                    slot = ips[ip] = [0, 0, 0]
                slot[0] += 1
                slot[1] += any_hit
                slot[2] += st == 401
            key = path.split(b"?", 1)[0][: PATH_KEY - 1]
            if key:
                if key not in paths_t and len(paths_t) >= PATH_MAX_LOAD:
                    path_over += 1
                else:
                    paths_t[key] = paths_t.get(key, 0) + 1

    def arr(name, label, rows):
        return ',"%s":[%s]' % (name, ",".join('{"%s":%s,"count":%d}' % (label, jstr(k), v) for k, v in rows))

    s = '{"lines":%d,"parsed":%d,"malformed":%d,"bytes":%d,"first_ts":%d,"last_ts":%d' % (lines, parsed, malformed, nbytes, first or 0, last or 0)
    s += ',"status":{%s}' % ",".join('"%dxx":%d' % (i + 1, status[i]) for i in range(5))
    s += ',"unique_ips":%d,"ip_overflow":%d,"unique_paths":%d,"path_overflow":%d,"attack_lines":%d' % (len(ips), ip_over, len(paths_t), path_over, attack_lines)
    s += ',"attacks":{%s}' % ",".join('"%s":%d' % (RULES[i], rules[i]) for i in range(7))
    s += arr("top_ips", "ip", top([(k, v[0]) for k, v in ips.items()], 1))
    s += arr("attackers", "ip", top([(k, v[1]) for k, v in ips.items()], 1))
    s += arr("auth_failures", "ip", top([(k, v[2]) for k, v in ips.items()], BRUTE_MIN))
    s += arr("top_paths", "path", top(list(paths_t.items()), 1))
    return s + "}"


if __name__ == "__main__":
    if len(sys.argv) < 2:
        sys.exit("usage: ref.py access.log [more.log ...]")
    print(analyze(sys.argv[1:]))
