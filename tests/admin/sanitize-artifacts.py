#!/usr/bin/env python3
"""Redact ephemeral canary credentials from text failure evidence before retaining it."""
from pathlib import Path
import re
import sys
from urllib.parse import urlsplit, parse_qs

run = Path(sys.argv[1])
secrets = set()
for name in ("candidate.env", "browser.env", "tester.env"):
    path = run / name
    if path.exists():
        for line in path.read_text().splitlines():
            key, _, value = line.partition("=")
            if key in ("PINGAP_ADMIN_PASSWORD", "PINGAP_E2E_PASSWORD", "PASSWORD") and value:
                secrets.add(value)
            if key == "PINGAP_ADMIN_ADDR":
                for secret in parse_qs(urlsplit("http://" + value).query).get("totp_key", []):
                    secrets.add(secret)
for root in (run, Path(sys.argv[2])):
    if not root.exists():
        continue
    for path in root.rglob("*"):
        if not path.is_file() or path.suffix not in (".log", ".md", ".txt", ".json", ".html", ".xml"):
            continue
        before = path.read_text(errors="replace")
        after = before
        for secret in secrets:
            after = after.replace(secret, "[REDACTED_CANARY_PASSWORD]")
        after = re.sub(r'(- textbox "Password": )[^\n]+', r'\1[REDACTED_CANARY_PASSWORD]', after)
        if before != after:
            path.write_text(after)
