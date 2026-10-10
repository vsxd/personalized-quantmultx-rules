#!/usr/bin/env python3
"""Small, dependency-free linter for Quantumult X rule lists."""
from __future__ import annotations

import ipaddress
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
RULE_TYPES = {
    "host", "host-suffix", "host-keyword", "host-wildcard",
    "ip-cidr", "ip6-cidr", "ip-cidr6", "geoip", "geoip6",
    "ip-asn", "user-agent", "url-regex", "final", "filter-lan",
    "filter-region", "via-interface",
}


def is_comment(line: str) -> bool:
    stripped = line.strip()
    return not stripped or stripped.startswith(("#", ";", "//"))


def lint(path: Path) -> list[str]:
    errors: list[str] = []
    seen: dict[tuple[str, ...], int] = {}
    for lineno, raw in enumerate(path.read_text(encoding="utf-8", errors="replace").splitlines(), 1):
        if is_comment(raw):
            continue
        fields = [part.strip() for part in raw.split(",")]
        kind = fields[0].lower()
        if kind not in RULE_TYPES:
            errors.append(f"{path.relative_to(ROOT)}:{lineno}: unsupported rule type {fields[0]!r}")
            continue
        if kind == "final":
            if len(fields) < 2 or not fields[1]:
                errors.append(f"{path.relative_to(ROOT)}:{lineno}: final has no policy")
            continue
        if len(fields) < 3 or not fields[1] or not fields[2]:
            errors.append(f"{path.relative_to(ROOT)}:{lineno}: expected type, value, policy")
            continue
        if kind in {"ip-cidr", "ip6-cidr", "ip-cidr6"}:
            try:
                ipaddress.ip_network(fields[1], strict=False)
            except ValueError as exc:
                errors.append(f"{path.relative_to(ROOT)}:{lineno}: invalid network {fields[1]!r}: {exc}")
        key = tuple(fields[:3])
        if key not in seen:
            seen[key] = lineno
    return errors


def main() -> int:
    files = sorted(ROOT.glob("*.list")) + sorted((ROOT / "Rules").rglob("*.list"))
    errors: list[str] = []
    for path in files:
        errors.extend(lint(path))
    if errors:
        print("\n".join(errors))
        return 1
    print(f"validated {len(files)} rule lists")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
