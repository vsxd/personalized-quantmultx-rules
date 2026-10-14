#!/usr/bin/env python3
"""Validate this repository's canonical Quantumult X routing-list subset.

This is a static linter, not the Quantumult X runtime. It deliberately rejects
foreign dialect aliases and resource names inside rule lists. Rule order,
force-policy overrides, DNS, and the device's selected group still need testing.
"""
from __future__ import annotations

import argparse
from collections import defaultdict
from dataclasses import asdict, dataclass
import ipaddress
import json
from pathlib import Path
import re
import sys

ROOT = Path(__file__).resolve().parents[1]
RULE_TYPES = {
    "host", "host-suffix", "host-keyword", "host-wildcard", "user-agent",
    "ip-cidr", "ip6-cidr", "geoip", "ip-asn", "final",
}
# Canonical options shown in crossutility/Quantumult-X/sample.conf.
INTERFACE_OPTIONS = {"force-cellular", "multi-interface", "multi-interface-balance"}
DOMAIN_LABEL = re.compile(r"[a-z0-9_](?:[a-z0-9_-]{0,61}[a-z0-9_])?", re.I)
DNS_OPTIONS = {"force-remote-dns"}
SHARED_SUFFIXES = {
    "amazonaws.com", "azureedge.net", "azurefd.net", "azurewebsites.net",
    "cloudfront.net", "cloudflare.com", "intercom.io", "sentry.io",
    "blob.core.windows.net", "windows.net", "akamaized.net", "akamai.net",
}


@dataclass(frozen=True)
class Diagnostic:
    severity: str
    code: str
    file: str
    line: int
    message: str


@dataclass(frozen=True)
class Rule:
    file: str
    line: int
    kind: str
    value: str
    policy: str
    options: tuple[str, ...]


def is_comment(line: str) -> bool:
    return not line.strip() or line.lstrip().startswith(("#", ";", "//"))


def valid_domain(value: str, wildcard: bool = False) -> bool:
    if not value or len(value) > 253 or value.endswith('.'):
        return False
    if wildcard:
        value = value.replace('*', 'a').replace('?', 'a')
    return all(DOMAIN_LABEL.fullmatch(label) for label in value.split('.'))


def inspect_text(text: str, filename: str = '<input>') -> tuple[list[Rule], list[Diagnostic]]:
    rules: list[Rule] = []
    diagnostics: list[Diagnostic] = []
    seen: dict[tuple, Rule] = {}
    targets: dict[tuple, Rule] = {}

    def add(line: int, severity: str, code: str, message: str) -> None:
        diagnostics.append(Diagnostic(severity, code, filename, line, message))

    for lineno, raw in enumerate(text.splitlines(), 1):
        if is_comment(raw):
            continue
        fields = [part.strip() for part in raw.split(',')]
        kind = fields[0].lower()
        if kind not in RULE_TYPES:
            add(lineno, 'error', 'rule-type', f'unsupported canonical rule type {fields[0]!r}')
            continue
        minimum = 2 if kind == 'final' else 3
        if len(fields) < minimum or any(not f for f in fields):
            add(lineno, 'error', 'fields', 'missing or empty rule field')
            continue
        if kind == 'final':
            value, policy, options = '', fields[1], tuple(fields[2:])
            add(lineno, 'warning', 'final-in-list', 'final in a reusable list can bypass later rules')
        else:
            value, policy, options = fields[1], fields[2], tuple(fields[3:])
        for option in options:
            if option in DNS_OPTIONS:
                add(lineno, 'warning', 'dns-option', f'{option!r} is a DNS behavior override; verify the effective DNS path for the selected policy')
            elif option not in INTERFACE_OPTIONS and not re.fullmatch(r'via-interface=[A-Za-z0-9_.-]+', option):
                add(lineno, 'error', 'option', f'unverified or unsupported option {option!r}; do not mix rule dialects')
        if len(set(options)) != len(options):
            add(lineno, 'error', 'option-duplicate', 'duplicate rule option')
        interface_options = [o for o in options if o in INTERFACE_OPTIONS or o.startswith('via-interface=')]
        if len(interface_options) > 1:
            add(lineno, 'error', 'option-conflict', 'choose one interface routing option')
        if any(ord(c) < 32 for c in value + policy) or '\ufffd' in value + policy:
            add(lineno, 'error', 'encoding', 'control character or invalid UTF-8 replacement')
        if kind in {'host', 'host-suffix', 'host-wildcard'}:
            if not valid_domain(value, wildcard=kind == 'host-wildcard'):
                add(lineno, 'error', 'domain', f'invalid domain or wildcard {value!r}')
            if kind == 'host-wildcard':
                if not any(c in value for c in '*?'):
                    add(lineno, 'warning', 'wildcard-empty', 'wildcard rule contains no wildcard')
                if '*' in value.split('.')[-1] or '?' in value.split('.')[-1]:
                    add(lineno, 'warning', 'wildcard-tld', 'wildcard can match unrelated domains; prefer verified suffixes')
            elif kind == 'host-suffix' and value.lower() in SHARED_SUFFIXES:
                add(lineno, 'warning', 'shared-domain', 'shared infrastructure suffix affects other services')
        if kind == 'host-keyword':
            if re.search(r'\s', value):
                add(lineno, 'error', 'keyword', 'hostname keyword contains whitespace')
            add(lineno, 'warning', 'broad-keyword', f'keyword {value!r} also matches unrelated hostnames')
        if kind in {'ip-cidr', 'ip6-cidr'}:
            if '/' not in value:
                add(lineno, 'error', 'cidr-prefix', 'CIDR prefix is required, including /32 or /128 for one IP')
            try:
                network = ipaddress.ip_network(value, strict=True)
                expected = 4 if kind == 'ip-cidr' else 6
                if network.version != expected:
                    add(lineno, 'error', 'cidr-family', f'{kind} requires IPv{expected}')
                if network.prefixlen == 0:
                    add(lineno, 'error', 'cidr-default', '/0 captures the entire address family')
                elif network.prefixlen < (24 if expected == 4 else 48):
                    add(lineno, 'warning', 'broad-cidr', f'large network {network} needs ownership and scope review')
            except ValueError as exc:
                add(lineno, 'error', 'cidr', str(exc))
        if kind == 'geoip' and not re.fullmatch(r'[A-Za-z]{2}', value):
            add(lineno, 'error', 'geoip', 'geoip needs a two-letter country code')
        if kind == 'ip-asn' and (not value.isdigit() or not 1 <= int(value) <= 4294967295):
            add(lineno, 'error', 'asn', 'ASN must be an integer from 1 to 4294967295')
        rule = Rule(filename, lineno, kind, value, policy, options)
        # Values used for domains/IP/ASN are case-insensitive; user-agent case is preserved.
        target_value = value if kind == 'user-agent' else value.lower()
        target = (kind, target_value)
        key = (*target, policy, options)
        if key in seen:
            add(lineno, 'warning', 'duplicate', f'exact duplicate of line {seen[key].line}')
        elif target in targets and targets[target].policy != policy:
            add(lineno, 'warning', 'policy-conflict', f'same target has policy {targets[target].policy!r} at line {targets[target].line}; force-policy may override both')
        seen.setdefault(key, rule)
        targets.setdefault(target, rule)
        rules.append(rule)
    if not rules:
        add(1, 'error', 'empty-list', 'rule list has no parsed rules')
    return rules, diagnostics


def inspect_files(paths: list[Path], root: Path = ROOT) -> tuple[list[Rule], list[Diagnostic]]:
    all_rules: list[Rule] = []
    diagnostics: list[Diagnostic] = []
    for path in paths:
        try:
            name = str(path.relative_to(root))
        except ValueError:
            name = str(path)
        try:
            text = path.read_text(encoding='utf-8')
        except (UnicodeError, OSError) as exc:
            diagnostics.append(Diagnostic('error', 'read', name, 1, str(exc)))
            continue
        rules, findings = inspect_text(text, name)
        all_rules.extend(rules)
        diagnostics.extend(findings)
    by_target: dict[tuple, list[Rule]] = defaultdict(list)
    for rule in all_rules:
        value = rule.value if rule.kind == 'user-agent' else rule.value.lower()
        by_target[(rule.kind, value)].append(rule)
    for matches in by_target.values():
        files = sorted({r.file for r in matches})
        if len(files) > 1:
            first = matches[0]
            diagnostics.append(Diagnostic('warning', 'cross-list-overlap', first.file, first.line,
                                          f'{first.kind},{first.value} also appears in {", ".join(f for f in files if f != first.file)}; check consumer ordering/force-policy'))
    return all_rules, diagnostics


def validate_policy_references(
    rules: list[Rule], known_policies: set[str],
    force_policies: dict[str, str] | None = None,
) -> list[Diagnostic]:
    """Validate effective policy names against a consuming config's inventory.

    Callers must supply custom groups and available node tags. force_policies is
    keyed by the Rule.file identifier. It is essential to check the forced value,
    not an ignored source label (e.g. Foreign Media becomes Global).
    """
    allowed = {'direct', 'proxy', 'reject'} | known_policies
    forced = force_policies or {}
    diagnostics = []
    for rule in rules:
        policy = forced.get(rule.file, rule.policy)
        if policy not in allowed and policy.lower() not in {'direct', 'proxy', 'reject'}:
            diagnostics.append(Diagnostic('error', 'policy-reference', rule.file, rule.line,
                                          f'effective policy {policy!r} is absent from the supplied policy inventory'))
    return diagnostics


def lint(path: Path) -> list[str]:
    """Compatibility helper returning error messages for one file."""
    _, diagnostics = inspect_files([path])
    return [f'{d.file}:{d.line}: {d.message}' for d in diagnostics if d.severity == 'error']


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('paths', nargs='*', type=Path, help='list files; defaults to root *.list and Rules/**/*.list')
    parser.add_argument('--json', action='store_true', help='emit all diagnostic details as JSON')
    parser.add_argument('--warnings-as-errors', action='store_true')
    args = parser.parse_args(argv)
    files = args.paths or sorted(ROOT.glob('*.list')) + sorted((ROOT / 'Rules').rglob('*.list'))
    if not files:
        print('error: no rule lists found', file=sys.stderr)
        return 1
    rules, diagnostics = inspect_files(files)
    errors = [d for d in diagnostics if d.severity == 'error']
    warnings = [d for d in diagnostics if d.severity == 'warning']
    if args.json:
        print(json.dumps({'files': len(files), 'rules': len(rules), 'errors': len(errors),
                          'warnings': len(warnings), 'diagnostics': [asdict(d) for d in diagnostics]}, indent=2, ensure_ascii=False))
    else:
        for diagnostic in errors:
            print(f'{diagnostic.file}:{diagnostic.line}: {diagnostic.severity} [{diagnostic.code}] {diagnostic.message}')
        counts: dict[str, int] = defaultdict(int)
        for diagnostic in warnings:
            counts[diagnostic.code] += 1
        for code, count in sorted(counts.items()):
            print(f'warning [{code}]: {count} (use --json for locations)')
        print(f'checked {len(files)} rule lists, {len(rules)} rules: {len(errors)} errors, {len(warnings)} warnings')
    return int(bool(errors) or bool(args.warnings_as_errors and warnings))


if __name__ == '__main__':
    raise SystemExit(main())
