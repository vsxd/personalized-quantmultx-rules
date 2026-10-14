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
import io
import json
from pathlib import Path, PurePosixPath
import re
import shutil
import subprocess
import sys
import tarfile
import time
from urllib.error import HTTPError, URLError
from urllib.parse import quote, urlsplit
from urllib.request import Request, urlopen

ROOT = Path(__file__).resolve().parents[1]
RULE_TYPES = {"host", "host-suffix", "host-keyword", "host-wildcard", "user-agent",
              "ip-cidr", "ip6-cidr", "geoip", "ip-asn", "final"}
MAX_BYTES = 20 * 1024 * 1024
SOURCE_FORMATS = {"qx", "surge", "domainset", "domain-list", "text"}
SURGE_TYPES = {"domain", "domain-suffix", "domain-keyword", "domain-wildcard",
               "ip-cidr", "ip-cidr6", "geoip", "ip-asn", "user-agent",
               "process-name", "url-regex", "and", "or", "not", "rule-set",
               "dest-port", "src-port", "in-port", "protocol", "subnet", "cellular-radio"}



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


def inventory(data: bytes, source_format: str = "qx") -> dict:
    """Normalize formatting, retaining policy/options and exposing order changes.

    This is an inventory, not QX emulation. Unknown/malformed lines are retained
    verbatim and reported so changed upstream formats cannot silently disappear.
    """
    if source_format not in SOURCE_FORMATS:
        raise ValueError(f"unsupported reference format {source_format!r}")
    ordered: list[str] = []
    anomalies: list[dict] = []
    directives: list[dict] = []
    for lineno, raw in enumerate(data.decode("utf-8-sig").splitlines(), 1):
        line = raw.strip()
        if not line or line.startswith(("#", ";", "//")):
            continue
        if source_format == "text":
            ordered.append(line)
            continue
        if source_format == "domain-list":
            # v2fly directives remain native evidence, never translated into QX.
            # Include dependency graphs are inspected separately, not imported.
            # Regex case is significant and is preserved.
            value = re.split(r"\s+#", line, maxsplit=1)[0].strip()
            if not value:
                continue
            target, *attributes = value.split()
            kind, separator, domain = target.partition(":")
            if not separator:
                kind, domain = "domain", target
            if (kind not in {"domain", "full", "keyword", "regexp", "include"} or not domain
                    or any(not re.fullmatch(r"@-?!?[A-Za-z0-9_-]+(?:=[A-Za-z0-9_-]+)?", a) for a in attributes)
                    or (kind == "include" and not re.fullmatch(r"[A-Za-z0-9_!-][A-Za-z0-9_!.-]*", domain))):
                anomalies.append({"line": lineno, "text": line, "reason": "unknown domain-list directive"})
                ordered.append("UNPARSED:" + line)
                continue
            if kind in {"include", "regexp"}:
                directives.append({"line": lineno, "kind": kind, "value": domain, "attributes": attributes})
            if kind not in {"regexp", "include"}:
                domain = domain.lower()
            ordered.append(kind + ":" + domain + (" " + " ".join(attributes) if attributes else ""))
            continue
        if source_format == "domainset":
            # Surge DOMAIN-SET: a leading dot includes descendants; otherwise
            # the target is exact. Never erase this distinction.
            # Source-domainsets may annotate a target with a whitespace comment.
            value = re.split(r"\s+#", line, maxsplit=1)[0].strip()
            target = value[1:] if value.startswith(".") else value
            if (not target or any(c.isspace() for c in target) or any(c in target for c in ",:/@*\\")
                    or any(not label or label.startswith("-") or label.endswith("-") for label in target.split("."))):
                anomalies.append({"line": lineno, "text": line, "reason": "malformed domainset target"})
                ordered.append("UNPARSED:" + line)
            else:
                ordered.append(("suffix:" if value.startswith(".") else "exact:") + target.lower())
            continue
        fields = [part.strip() for part in line.split(",")]
        kind = fields[0].lower()
        if source_format == "surge":
            # Surge rule-provider files usually omit policies. Preserve native
            # names/options rather than claiming these are valid QX rules.
            if kind not in SURGE_TYPES or len(fields) < 2 or any(not field for field in fields):
                anomalies.append({"line": lineno, "text": line, "reason": "unknown Surge type or malformed fields"})
                ordered.append("UNPARSED:" + line)
            else:
                fields[0] = kind
                if kind in {"domain", "domain-suffix", "domain-keyword", "domain-wildcard"}:
                    fields[1] = fields[1].lower()
                ordered.append(",".join(fields))
            continue
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
        "format": source_format, "line_count": len(ordered), "unique_count": len(counts),
        "reference_directives": directives,
        "ordered_semantic_sha256": sha256("\n".join(ordered).encode()),
        "duplicates": {rule: n for rule, n in sorted(counts.items()) if n > 1},
        "anomalies": anomalies, "rules": sorted(counts),
    }


def write_json(path: Path, value: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")


def compare_file(out: Path, name: str, slug: str, baseline: str, latest: str,
                 path: str, expected_sha: str | None, source_format: str = "qx") -> dict:
    old, old_url = download(slug, baseline, path)
    if expected_sha and sha256(old) != expected_sha:
        # Preserve rejected public input for diagnosis; never parse or adopt it.
        rejected = out / name / "rejected-baseline" / checked_path(path)
        rejected.parent.mkdir(parents=True, exist_ok=True)
        rejected.write_bytes(old)
        write_json(rejected.with_name(rejected.name + ".failure.json"), {
            "url": old_url, "expected_sha256": expected_sha, "actual_sha256": sha256(old)})
        raise ValueError(f"{name}/{path}: pinned baseline SHA256 mismatch; stop and investigate")
    new, new_url = (old, old_url) if baseline == latest else download(slug, latest, path)
    old_inventory, new_inventory = inventory(old, source_format), inventory(new, source_format)
    for label, data, info in (("baseline", old, old_inventory), ("latest", new, new_inventory)):
        target = out / name / label / checked_path(path)
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(data)
        write_json(target.with_name(target.name + ".inventory.json"), info)
    old_rules, new_rules = set(old_inventory["rules"]), set(new_inventory["rules"])
    delta = {
        "path": path, "format": source_format, "baseline_commit": baseline, "latest_commit": latest,
        "baseline_url": old_url, "latest_url": new_url,
        "baseline_sha256": sha256(old), "latest_sha256": sha256(new),
        "baseline_hash_verified_against_lock": bool(expected_sha),
        "baseline_unique_rules": len(old_rules), "latest_unique_rules": len(new_rules),
        "added": sorted(new_rules - old_rules), "removed": sorted(old_rules - new_rules),
        "ordered_semantics_changed": old_inventory["ordered_semantic_sha256"] != new_inventory["ordered_semantic_sha256"],
        "duplicate_counts_changed": old_inventory["duplicates"] != new_inventory["duplicates"],
        "baseline_anomalies": old_inventory["anomalies"], "latest_anomalies": new_inventory["anomalies"],
        "baseline_reference_directives": old_inventory["reference_directives"],
        "latest_reference_directives": new_inventory["reference_directives"],
    }
    write_json(out / name / "diffs" / (checked_path(path) + ".json"), delta)
    return delta


def compare_license(out: Path, name: str, slug: str, old: str, new: str,
                    license_path: str = "LICENSE", expected_sha: str | None = None) -> dict:
    before, before_url = download(slug, old, license_path)
    if expected_sha and sha256(before) != expected_sha:
        raise ValueError("pinned license SHA256 mismatch; stop and investigate")
    after, after_url = (before, before_url) if old == new else download(slug, new, license_path)
    for label, content in (("baseline", before), ("latest", after)):
        path = out / name / label / checked_path(license_path)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(content)
    return {"path": license_path, "baseline_commit": old, "latest_commit": new,
            "baseline_hash_verified_against_lock": bool(expected_sha),
            "baseline_url": before_url, "latest_url": after_url,
            "baseline_sha256": sha256(before), "latest_sha256": sha256(after),
            "changed": before != after}


def github_tree(slug: str, tree_sha: str, recursive: bool = False) -> dict:
    """Read a bounded public Git tree. Truncation is never a complete inventory."""
    checked_commit(tree_sha)
    suffix = "?recursive=1" if recursive else ""
    url = f"https://api.github.com/repos/{slug}/git/trees/{tree_sha}{suffix}"
    if shutil.which("gh"):
        # gh uses its own configured credentials without exposing them here.
        # A failed authenticated call is a real error, not an empty inventory.
        response = subprocess.run(["gh", "api", f"repos/{slug}/git/trees/{tree_sha}{suffix}"],
                                  check=True, capture_output=True, timeout=60)
        data = response.stdout
    else:
        request = Request(url, headers={"User-Agent": "personalized-quantmultx-rules-upstream-audit/1",
                                        "Accept": "application/vnd.github+json"})
        with urlopen(request, timeout=30) as response:
            data = response.read(MAX_BYTES + 1)
    if len(data) > MAX_BYTES:
        raise ValueError("Git tree exceeds download limit; choose narrower inventory_paths")
    result = json.loads(data)
    if result.get("truncated"):
        raise ValueError("GitHub truncated tree inventory; choose narrower inventory_paths")
    if not isinstance(result.get("tree"), list):
        raise ValueError("GitHub did not return a Git tree")
    return result


def tree_inventory(slug: str, commit: str, paths: list[str]) -> dict[str, str]:
    """Inventory only configured subtrees, without downloading their contents."""
    entries: dict[str, str] = {}
    cache: dict[tuple[str, bool], dict] = {}
    def read(sha: str, recursive: bool = False) -> dict:
        key = (sha, recursive)
        if key not in cache:
            cache[key] = github_tree(slug, sha, recursive)
        return cache[key]
    for prefix in paths:
        prefix = checked_path(prefix).rstrip("/")
        sha = checked_commit(commit)
        kind = "tree"
        if prefix != ".":
            for part in PurePosixPath(prefix).parts:
                if kind != "tree":
                    raise ValueError(f"inventory path descends through a file: {prefix}")
                matches = [item for item in read(sha)["tree"] if item.get("path") == part]
                if not matches:
                    # Absence matters when a directory is added/deleted. A valid
                    # tree with no entry is different from an HTTP/API failure.
                    sha = ""
                    break
                if len(matches) != 1:
                    raise ValueError(f"ambiguous inventory path: {prefix}")
                sha, kind = matches[0]["sha"], matches[0]["type"]
        if not sha:
            continue
        if kind == "blob":
            entries[prefix] = sha
        elif kind == "tree":
            for item in read(sha, True)["tree"]:
                if item["type"] == "blob":
                    path = checked_path(item["path"])
                    entries[path if prefix == "." else prefix + "/" + path] = item["sha"]
        else:
            raise ValueError(f"unsupported inventory entry type {kind!r}: {prefix}")
    return dict(sorted(entries.items()))


def compare_tree(out: Path, name: str, slug: str, old: str, new: str, paths: list[str]) -> dict:
    before = tree_inventory(slug, old, paths)
    after = before if old == new else tree_inventory(slug, new, paths)
    if not before and not after:
        raise ValueError("configured inventory paths contain no files at either revision; check the scope")
    result = {"paths": paths, "baseline_files": len(before), "latest_files": len(after),
              "added_paths": sorted(after.keys() - before.keys()),
              "removed_paths": sorted(before.keys() - after.keys()),
              "changed_paths": sorted(path for path in before.keys() & after.keys() if before[path] != after[path]),
              "content_reviewed": False}
    write_json(out / name / "tree-baseline.json", before)
    write_json(out / name / "tree-latest.json", after)
    write_json(out / name / "tree-diff.json", result)
    return result


def domain_archive(slug: str, commit: str, directory: str) -> dict[str, bytes]:
    """Read a bounded immutable source archive without extracting executable files.

    A v2fly category may reference most of data/. One public source archive avoids
    thousands of raw HTTP requests. Only regular files in the configured data
    directory are kept; archive paths/links never reach filesystem extraction.
    """
    directory = checked_path(directory).rstrip("/")
    if directory == ".":
        raise ValueError("dependency directory must be a specific subtree")
    url = f"https://codeload.github.com/{slug}/tar.gz/{checked_commit(commit)}"
    request = Request(url, headers={"User-Agent": "personalized-quantmultx-rules-upstream-audit/1"})
    with urlopen(request, timeout=60) as response:
        data = response.read(MAX_BYTES + 1)
    if len(data) > MAX_BYTES:
        raise ValueError("dependency archive exceeds compressed size limit")
    entries: dict[str, bytes] = {}
    total = 0
    with tarfile.open(fileobj=io.BytesIO(data), mode="r:gz") as archive:
        for index, member in enumerate(archive):
            if index >= 20000:
                raise ValueError("dependency archive has too many entries")
            parts = PurePosixPath(checked_path(member.name)).parts
            if len(parts) < 2:
                continue
            path = "/".join(parts[1:])
            if not path.startswith(directory + "/") or member.isdir():
                continue
            if not member.isfile() or member.size > MAX_BYTES:
                raise ValueError(f"unsupported dependency archive entry: {path}")
            total += member.size
            if total > 100 * 1024 * 1024:
                raise ValueError("dependency archive exceeds expanded size limit")
            if path in entries:
                raise ValueError(f"duplicate dependency archive entry: {path}")
            stream = archive.extractfile(member)
            if stream is None:
                raise ValueError(f"unreadable dependency archive entry: {path}")
            entries[path] = stream.read()
    if not entries:
        raise ValueError("dependency archive has no files in configured directory")
    return entries


def dependency_inventory(contents: dict[str, bytes], roots: list[str], directory: str) -> dict:
    """Inventory full include closure, preserving attributes without applying them.

    This is dependency discovery, not an expansion of filtered routing rules.
    Even filtered includes are inspected so changes hidden behind an unchanged
    parent list remain visible. Missing dependencies, cycles and unknown syntax
    make the comparison incomplete instead of producing false zero differences.
    """
    directory = checked_path(directory).rstrip("/")
    roots = sorted({checked_path(path) for path in roots})
    if not roots:
        raise ValueError("dependency inventory needs at least one root")
    if any(not path.startswith(directory + "/") for path in roots):
        raise ValueError("dependency root is outside the configured directory")
    files: dict[str, dict] = {}
    errors: list[str] = []
    active: list[str] = []
    visited: set[str] = set()

    def visit(path: str) -> None:
        if path in active:
            errors.append("include cycle: " + " -> ".join(active[active.index(path):] + [path]))
            return
        if path in visited:
            return
        visited.add(path)
        if path not in contents:
            errors.append(f"missing included file: {path}")
            return
        try:
            info = inventory(contents[path], "domain-list")
        except (ValueError, UnicodeError) as exc:
            errors.append(f"{path}: {exc}")
            return
        files[path] = {"sha256": sha256(contents[path]), **info}
        if info["anomalies"]:
            errors.append(f"{path}: {len(info['anomalies'])} unparsed directive(s)")
        active.append(path)
        dependencies = {item["value"] for item in info["reference_directives"] if item["kind"] == "include"}
        for included in sorted(dependencies):
            visit(directory + "/" + included)
        active.pop()

    for root in roots:
        visit(root)
    return {"roots": roots, "directory": directory, "files": dict(sorted(files.items())),
            "errors": sorted(set(errors)), "expanded_into_rules": False}


def compare_dependencies(out: Path, name: str, slug: str, old: str, new: str,
                         config: dict, selected_files: list[dict]) -> dict:
    directory = checked_path(config["directory"])
    roots = config["roots"]
    before_data = domain_archive(slug, old, directory)
    after_data = before_data if old == new else domain_archive(slug, new, directory)
    # Cross-check selected archived baseline bytes against the same raw-file lock.
    for item in selected_files:
        path = item["path"]
        if path in before_data and item.get("sha256") and sha256(before_data[path]) != item["sha256"]:
            raise ValueError(f"dependency archive {path}: pinned baseline SHA256 mismatch")
    before = dependency_inventory(before_data, roots, directory)
    after = before if old == new else dependency_inventory(after_data, roots, directory)
    a, b = before["files"], after["files"]
    changed = sorted(path for path in a.keys() & b.keys() if a[path]["sha256"] != b[path]["sha256"])
    result = {"directory": directory, "roots": sorted(roots),
              "baseline_files": len(a), "latest_files": len(b),
              "added_paths": sorted(b.keys() - a.keys()), "removed_paths": sorted(a.keys() - b.keys()),
              "changed_paths": changed, "expanded_into_rules": False,
              "baseline_errors": before["errors"], "latest_errors": after["errors"]}
    for label, data, info in (("baseline", before_data, before), ("latest", after_data, after)):
        write_json(out / name / "dependencies" / (label + ".json"), info)
        for path in info["files"]:
            target = out / name / "dependencies" / label / checked_path(path)
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(data[path])
    # Content deltas include indirect children, even when root bytes do not change.
    for path in changed:
        old_rules, new_rules = set(a[path]["rules"]), set(b[path]["rules"])
        write_json(out / name / "dependencies" / "diffs" / (path + ".json"), {
            "path": path, "added": sorted(new_rules - old_rules), "removed": sorted(old_rules - new_rules),
            "baseline_sha256": a[path]["sha256"], "latest_sha256": b[path]["sha256"],
            "ordered_semantics_changed": a[path]["ordered_semantic_sha256"] != b[path]["ordered_semantic_sha256"],
        })
    write_json(out / name / "dependencies" / "diff.json", result)
    return result


def check_source(out: Path, name: str, source: dict, workers: int) -> dict:
    if not re.fullmatch(r"[A-Za-z0-9_-]+", name):
        raise ValueError("source name must be a simple alphanumeric identifier")
    slug = repository_slug(source["repository"])
    branch = source.get("rule_branch") or source["source_branch"]
    baseline = checked_commit(source.get("rule_commit") or source["commit"])
    latest = resolve_branch(slug, branch)
    files = source.get("reference_files", source.get("files"))
    if files is None:
        files = []
    files = list(files) + ([source["repair_reference"]] if source.get("repair_reference") else [])
    if not files and not source.get("inventory_paths") and not (
            source.get("comparison_scope") == "reference-only" and source.get("reason")):
        raise ValueError("source has no selected files or inventory scope; declare an explained reference-only scope")
    if len({checked_path(item["path"]) for item in files}) != len(files):
        raise ValueError("duplicate selected reference file path")
    license_old = checked_commit(source.get("license_commit") or baseline)
    license_branch = source.get("license_branch", branch)
    license_new = latest if license_branch == branch else resolve_branch(slug, license_branch)
    result = {"repository": source["repository"], "branch": branch,
              "baseline_commit": baseline, "latest_commit": latest,
              "revision_changed": baseline != latest, "declared_license": source.get("license"),
              "license_baseline_commit": license_old, "license_latest_commit": license_new,
              "files": [], "errors": [], "validation_issues": []}
    license_path = source.get("license_path", "LICENSE")
    if license_path is None:
        result["license"] = {"skipped": True, "reason": "No license file declared; do not infer permission to copy"}
    else:
        try:
            result["license"] = compare_license(out, name, slug, license_old, license_new,
                                                checked_path(license_path), source.get("license_sha256"))
        except Exception as exc:
            result["errors"].append(f"LICENSE: {exc}")
    with ThreadPoolExecutor(max_workers=workers) as pool:
        futures = {pool.submit(compare_file, out, name, slug, baseline, latest,
                               checked_path(item["path"]), item.get("sha256"),
                               item.get("format", source.get("format", "qx"))): item["path"]
                   for item in files}
        for future in as_completed(futures):
            try:
                compared = future.result()
                result["files"].append(compared)
                if compared.get("baseline_anomalies") or compared.get("latest_anomalies"):
                    issue = f"{compared['path']}: unparsed/malformed reference lines; inspect inventories"
                    result["errors"].append(issue)
                    result["validation_issues"].append(issue)
            except Exception as exc:
                result["errors"].append(f"{futures[future]}: {exc}")
    if source.get("inventory_paths"):
        try:
            result["tree_inventory"] = compare_tree(out, name, slug, baseline, latest, source["inventory_paths"])
        except Exception as exc:
            result["errors"].append(f"TREE INVENTORY: {exc}")
    if source.get("dependencies"):
        try:
            result["dependencies"] = compare_dependencies(out, name, slug, baseline, latest, source["dependencies"], files)
            if result["dependencies"]["baseline_errors"] or result["dependencies"]["latest_errors"]:
                result["errors"].append("DEPENDENCIES: incomplete include graph; inspect dependencies/*.json")
        except Exception as exc:
            result["errors"].append(f"DEPENDENCIES: {exc}")
    result["files"].sort(key=lambda item: item["path"])
    result["errors"].sort()
    result["validation_issues"].sort()
    result["comparison_complete"] = not (set(result["errors"]) - set(result["validation_issues"]))
    result["status"] = ("INCOMPLETE" if not result["comparison_complete"] else
                        "REVIEW_REQUIRED" if result["validation_issues"] else "COMPLETE")
    return result


def markdown_report(report: dict) -> str:
    lines = ["# Upstream comparison", "", f"Checked at {report['checked_at']}.", "",
             "This report proposes no automatic adoption. Local rules and upstream-lock.json are unchanged.",
             "Policy/options are part of each semantic rule; ordering and duplicates are reported separately.",
             "This is not a runtime routing simulation. Invalid upstream lines remain visible in inventories.", ""]
    for name, source in report["sources"].items():
        lines += [f"## {name}", "", f"Status: {source.get('status', 'INCOMPLETE' if source.get('errors') else 'COMPLETE')}.", ""]
        if "latest_commit" in source:
            lines += [f"Baseline: `{source['baseline_commit']}`; latest `{source['branch']}`: `{source['latest_commit']}`.", "",
                      "| File (source format) | Baseline rules | Latest rules | Added | Removed | Order/content changed | Anomalies |",
                      "| --- | ---: | ---: | ---: | ---: | --- | ---: |"]
            for item in source["files"]:
                lines.append(f"| {item['path']} ({item.get('format', 'qx')}) | {item['baseline_unique_rules']} | {item['latest_unique_rules']} | "
                             f"{len(item['added'])} | {len(item['removed'])} | {item['ordered_semantics_changed']} | {len(item['latest_anomalies'])} |")
            tree = source.get("tree_inventory")
            if tree:
                lines += ["", f"Tree inventory: {tree['latest_files']} files; {len(tree['added_paths'])} added, "
                          f"{len(tree['removed_paths'])} removed, {len(tree['changed_paths'])} changed. "
                          "See tree-diff.json for all paths; files outside the selected reference list were not content-reviewed."]
            dependencies = source.get("dependencies")
            if dependencies:
                lines += ["", f"Include closure: {dependencies['baseline_files']} baseline / "
                          f"{dependencies['latest_files']} latest files; {len(dependencies['added_paths'])} added, "
                          f"{len(dependencies['removed_paths'])} removed, {len(dependencies['changed_paths'])} changed. "
                          "Native directives and filters remain evidence; nothing is expanded into local routing rules. "
                          "See dependencies/diff.json and dependencies/diffs/."]
            if source.get("license", {}).get("skipped"):
                lines += ["", source["license"]["reason"]]
            lines += ["", f"Declared license: {source.get('declared_license')}; license text changed: {source.get('license', {}).get('changed', 'check failed')}.", ""]
        for error in source.get("errors", []):
            lines += [f"- ERROR: {error}"]
        lines.append("")
    lines += ["Full additions/removals, URLs, hashes, anomalies and duplicate changes are in report.json and source/diffs/.",
              "REVIEW_REQUIRED means configured comparisons finished but source syntax defects remain; INCOMPLETE means a fetch, integrity, inventory or dependency-graph check did not finish successfully. Both exit nonzero. Neither status is a local corpus test result.",
              "Review licensing, evidence, ownership/conflicts and route regressions before selectively editing local categories.",
              "Do not advance the baseline just because this check completed.", ""]
    return "\n".join(lines)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", default="all", help="source name from lock, or all (default)")
    parser.add_argument("--lock", type=Path, default=ROOT / "upstream-lock.json")
    parser.add_argument("--output-root", type=Path, default=ROOT / "work" / "upstream-check")
    parser.add_argument("--workers", type=int, default=4, choices=range(1, 9), metavar="1..8")
    args = parser.parse_args(argv)
    lock_bytes = args.lock.read_bytes()
    lock = json.loads(lock_bytes)
    available = lock.get("sources", {})
    if args.source != "all" and args.source not in available:
        parser.error(f"unknown source {args.source!r}; choose all or {', '.join(available)}")
    if not available:
        parser.error("lock contains no sources")
    now = datetime.now(timezone.utc)
    out = args.output_root / now.strftime("%Y%m%dT%H%M%S.%fZ")
    out.mkdir(parents=True, exist_ok=False)
    report = {"checked_at": now.isoformat(), "lock_sha256": sha256(lock_bytes), "sources": {}}
    names = tuple(available) if args.source == "all" else (args.source,)
    for name in names:
        print(f"Checking {name}...", flush=True)
        try:
            report["sources"][name] = check_source(out, name, lock["sources"][name], args.workers)
        except Exception as exc:
            report["sources"][name] = {"status": "INCOMPLETE", "errors": [str(exc)]}
    failed = any(source.get("errors") for source in report["sources"].values())
    report["status"] = ("INCOMPLETE" if any(source.get("status") == "INCOMPLETE" for source in report["sources"].values()) else
                        "REVIEW_REQUIRED" if failed else "COMPLETE")
    write_json(out / "report.json", report)
    (out / "report.md").write_text(markdown_report(report), encoding="utf-8")
    print(f"{report['status']}: {out / 'report.md'}")
    print("No curated rules or lock baselines were changed.")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
