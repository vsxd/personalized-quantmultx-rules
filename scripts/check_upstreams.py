#!/usr/bin/env python3
"""Read-only upstream comparison; never modify curated rules or upstream-lock.json.

Python standard library + git are sufficient. Results and downloaded public files
are written below work/upstream-check/. Remote contents are data, never executed.
"""
from __future__ import annotations

import argparse
from collections import Counter
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone
import hashlib
import ipaddress
import json
from pathlib import Path, PurePosixPath
import re
import subprocess
import sys
import time
from urllib.error import HTTPError, URLError
from urllib.parse import quote, urlsplit
from urllib.request import Request, urlopen

ROOT = Path(__file__).resolve().parents[1]
PPMINA_FILES = [f"ruleset/{name}.txt" for name in
                ("direct", "proxy", "reject", "apple", "icloud", "telegramcidr")]
RULE_TYPES = {"host", "host-suffix", "host-keyword", "host-wildcard", "user-agent",
              "ip-cidr", "ip6-cidr", "geoip", "ip-asn", "final"}
MAX_BYTES = 20 * 1024 * 1024


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def repository_slug(url: str) -> str:
    parsed = urlsplit(url)
    if parsed.scheme != "https" or parsed.netloc != "github.com" or parsed.query or parsed.fragment:
        raise ValueError("upstream repository must be a plain https://github.com/owner/repo URL")
    slug = parsed.path.strip("/").removesuffix(".git")
    if not re.fullmatch(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+", slug):
        raise ValueError("invalid GitHub repository path")
    return slug


def checked_commit(value: str) -> str:
    if not re.fullmatch(r"[0-9a-f]{40}", value):
        raise ValueError(f"expected full immutable commit SHA, got {value!r}")
    return value


def checked_path(value: str) -> str:
    path = PurePosixPath(value)
    if path.is_absolute() or ".." in path.parts or not value or "\\" in value:
        raise ValueError(f"invalid relative upstream path {value!r}")
    return str(path)


def resolve_branch(slug: str, branch: str) -> str:
    if not re.fullmatch(r"[A-Za-z0-9_./-]+", branch):
        raise ValueError("invalid upstream branch")
    ref = f"refs/heads/{branch}"
    result = subprocess.run(
        ["git", "ls-remote", "--exit-code", f"https://github.com/{slug}.git", ref],
        check=True, text=True, capture_output=True, timeout=60,
    )
    matches = [line.split()[0] for line in result.stdout.splitlines()
               if len(line.split()) == 2 and line.split()[1] == ref]
    if len(matches) != 1:
        raise ValueError(f"could not resolve exactly one {slug}:{branch}")
    return checked_commit(matches[0])


def download(slug: str, commit: str, path: str) -> tuple[bytes, str]:
    url = f"https://raw.githubusercontent.com/{slug}/{checked_commit(commit)}/{quote(checked_path(path), safe='/')}"
    for attempt in range(3):
        try:
            request = Request(url, headers={"User-Agent": "personalized-quantmultx-rules-upstream-audit/1"})
            with urlopen(request, timeout=30) as response:
                data = response.read(MAX_BYTES + 1)
                if len(data) > MAX_BYTES:
                    raise ValueError(f"upstream file exceeds {MAX_BYTES} bytes: {path}")
                content_type = response.headers.get("Content-Type", "").lower()
                if "text/html" in content_type or data.lstrip().lower().startswith((b"<!doctype html", b"<html")):
                    raise ValueError(f"received HTML instead of source data: {path}")
                return data, url
        except HTTPError as exc:
            if exc.code not in {429, 500, 502, 503, 504} or attempt == 2:
                raise
        except (URLError, TimeoutError):
            if attempt == 2:
                raise
        time.sleep(attempt + 1)
    raise RuntimeError("download failed")


def inventory(data: bytes) -> dict:
    """Normalize formatting, retaining policy/options and exposing order changes.

    This is an inventory, not QX emulation. Unknown/malformed lines are retained
    verbatim and reported so changed upstream formats cannot silently disappear.
    """
    ordered: list[str] = []
    anomalies: list[dict] = []
    for lineno, raw in enumerate(data.decode("utf-8-sig").splitlines(), 1):
        line = raw.strip()
        if not line or line.startswith(("#", ";", "//")):
            continue
        fields = [part.strip() for part in line.split(",")]
        kind = fields[0].lower()
        minimum = 2 if kind == "final" else 3
        if kind not in RULE_TYPES or len(fields) < minimum or any(not field for field in fields):
            anomalies.append({"line": lineno, "text": line, "reason": "unknown type or malformed fields"})
            ordered.append("UNPARSED:" + line)
            continue
        fields[0] = kind
        if kind != "final" and kind != "user-agent":
            fields[1] = fields[1].lower()
        if kind in {"ip-cidr", "ip6-cidr"}:
            try:
                network = ipaddress.ip_network(fields[1], strict=True)
                if network.version != (4 if kind == "ip-cidr" else 6):
                    raise ValueError("address family mismatch")
                fields[1] = str(network)
            except ValueError as exc:
                anomalies.append({"line": lineno, "text": line, "reason": str(exc)})
        policy_index = 1 if kind == "final" else 2
        if fields[policy_index].lower() in {"direct", "proxy", "reject"}:
            fields[policy_index] = fields[policy_index].lower()
        ordered.append(",".join(fields))
    if not ordered:
        raise ValueError("upstream file contains no rule lines")
    counts = Counter(ordered)
    return {
        "line_count": len(ordered), "unique_count": len(counts),
        "ordered_semantic_sha256": sha256("\n".join(ordered).encode()),
        "duplicates": {rule: n for rule, n in sorted(counts.items()) if n > 1},
        "anomalies": anomalies, "rules": sorted(counts),
    }


def write_json(path: Path, value: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")


def compare_file(out: Path, name: str, slug: str, baseline: str, latest: str,
                 path: str, expected_sha: str | None) -> dict:
    old, old_url = download(slug, baseline, path)
    if expected_sha and sha256(old) != expected_sha:
        raise ValueError(f"{name}/{path}: pinned baseline SHA256 mismatch; stop and investigate")
    new, new_url = (old, old_url) if baseline == latest else download(slug, latest, path)
    old_inventory, new_inventory = inventory(old), inventory(new)
    for label, data, info in (("baseline", old, old_inventory), ("latest", new, new_inventory)):
        target = out / name / label / checked_path(path)
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(data)
        write_json(target.with_name(target.name + ".inventory.json"), info)
    old_rules, new_rules = set(old_inventory["rules"]), set(new_inventory["rules"])
    delta = {
        "path": path, "baseline_commit": baseline, "latest_commit": latest,
        "baseline_url": old_url, "latest_url": new_url,
        "baseline_sha256": sha256(old), "latest_sha256": sha256(new),
        "baseline_hash_verified_against_lock": bool(expected_sha),
        "baseline_unique_rules": len(old_rules), "latest_unique_rules": len(new_rules),
        "added": sorted(new_rules - old_rules), "removed": sorted(old_rules - new_rules),
        "ordered_semantics_changed": old_inventory["ordered_semantic_sha256"] != new_inventory["ordered_semantic_sha256"],
        "duplicate_counts_changed": old_inventory["duplicates"] != new_inventory["duplicates"],
        "baseline_anomalies": old_inventory["anomalies"], "latest_anomalies": new_inventory["anomalies"],
    }
    write_json(out / name / "diffs" / (checked_path(path) + ".json"), delta)
    return delta


def compare_license(out: Path, name: str, slug: str, old: str, new: str) -> dict:
    before, before_url = download(slug, old, "LICENSE")
    after, after_url = (before, before_url) if old == new else download(slug, new, "LICENSE")
    for label, content in (("baseline", before), ("latest", after)):
        path = out / name / label / "LICENSE"
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(content)
    return {"baseline_url": before_url, "latest_url": after_url,
            "baseline_sha256": sha256(before), "latest_sha256": sha256(after),
            "changed": before != after}


def check_source(out: Path, name: str, source: dict, workers: int) -> dict:
    slug = repository_slug(source["repository"])
    branch = source.get("release_branch", "release") if name == "ppmina" else source["source_branch"]
    baseline = checked_commit(source["release_commit"] if name == "ppmina" else source["commit"])
    latest = resolve_branch(slug, branch)
    files = ([{"path": path} for path in PPMINA_FILES] if name == "ppmina"
             else list(source["files"]) + ([source["repair_reference"]] if source.get("repair_reference") else []))
    license_old = checked_commit(source["source_commit"]) if name == "ppmina" else baseline
    license_new = resolve_branch(slug, source["source_branch"]) if name == "ppmina" else latest
    result = {"repository": source["repository"], "branch": branch,
              "baseline_commit": baseline, "latest_commit": latest,
              "revision_changed": baseline != latest, "declared_license": source.get("license"),
              "source_commit": license_new, "files": [], "errors": []}
    try:
        result["license"] = compare_license(out, name, slug, license_old, license_new)
    except Exception as exc:
        result["errors"].append(f"LICENSE: {exc}")
    with ThreadPoolExecutor(max_workers=workers) as pool:
        futures = {pool.submit(compare_file, out, name, slug, baseline, latest,
                               checked_path(item["path"]), item.get("sha256")): item["path"]
                   for item in files}
        for future in as_completed(futures):
            try:
                result["files"].append(future.result())
            except Exception as exc:
                result["errors"].append(f"{futures[future]}: {exc}")
    result["files"].sort(key=lambda item: item["path"])
    return result


def markdown_report(report: dict) -> str:
    lines = ["# Upstream comparison", "", f"Checked at {report['checked_at']}.", "",
             "This report proposes no automatic adoption. Local rules and upstream-lock.json are unchanged.",
             "Policy/options are part of each semantic rule; ordering and duplicates are reported separately.",
             "This is not a runtime routing simulation. Invalid upstream lines remain visible in inventories.", ""]
    for name, source in report["sources"].items():
        lines += [f"## {name}", ""]
        if "latest_commit" in source:
            lines += [f"Baseline: `{source['baseline_commit']}`; latest `{source['branch']}`: `{source['latest_commit']}`.", "",
                      "| File | Baseline rules | Latest rules | Added | Removed | Order/content changed |",
                      "| --- | ---: | ---: | ---: | ---: | --- |"]
            for item in source["files"]:
                lines.append(f"| {item['path']} | {item['baseline_unique_rules']} | {item['latest_unique_rules']} | "
                             f"{len(item['added'])} | {len(item['removed'])} | {item['ordered_semantics_changed']} |")
            lines += ["", f"Declared license: {source.get('declared_license')}; license text changed: {source.get('license', {}).get('changed', 'check failed')}.", ""]
        for error in source.get("errors", []):
            lines += [f"- ERROR: {error}"]
        lines.append("")
    lines += ["Full additions/removals, URLs, hashes, anomalies and duplicate changes are in report.json and source/diffs/.",
              "Review licensing, evidence, ownership/conflicts and route regressions before selectively editing local categories.",
              "Do not advance the baseline just because this check completed.", ""]
    return "\n".join(lines)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", choices=("all", "sve1r", "ppmina"), default="all")
    parser.add_argument("--lock", type=Path, default=ROOT / "upstream-lock.json")
    parser.add_argument("--output-root", type=Path, default=ROOT / "work" / "upstream-check")
    parser.add_argument("--workers", type=int, default=4, choices=range(1, 9), metavar="1..8")
    args = parser.parse_args(argv)
    lock_bytes = args.lock.read_bytes()
    lock = json.loads(lock_bytes)
    now = datetime.now(timezone.utc)
    out = args.output_root / now.strftime("%Y%m%dT%H%M%S.%fZ")
    out.mkdir(parents=True, exist_ok=False)
    report = {"checked_at": now.isoformat(), "lock_sha256": sha256(lock_bytes), "sources": {}}
    names = ("sve1r", "ppmina") if args.source == "all" else (args.source,)
    for name in names:
        print(f"Checking {name}...", flush=True)
        try:
            report["sources"][name] = check_source(out, name, lock["sources"][name], args.workers)
        except Exception as exc:
            report["sources"][name] = {"errors": [str(exc)]}
    write_json(out / "report.json", report)
    (out / "report.md").write_text(markdown_report(report), encoding="utf-8")
    failed = any(source.get("errors") for source in report["sources"].values())
    print(f"{'INCOMPLETE' if failed else 'COMPLETE'}: {out / 'report.md'}")
    print("No curated rules or lock baselines were changed.")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
