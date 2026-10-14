#!/usr/bin/env python3
"""Offline QX destination-boundary and assembled-profile audit.

This deliberately supports explicit HOST/suffix and dated app IP lists only.
It is not QX's matching engine and cannot prove reachability, ownership of an
ordinary registered domain, current GeoIP accuracy or runtime policy choices.
"""
from __future__ import annotations

import argparse
from collections import Counter
from dataclasses import asdict, dataclass
from datetime import date
from functools import lru_cache
import hashlib
import ipaddress
import json
from pathlib import Path
import re
import sys

sys.path.insert(0, str(Path(__file__).resolve().parent))
from validate_rules import Rule, inspect_text, validate_policy_references

ROOT = Path(__file__).resolve().parents[1]
DATA = ROOT / 'data/domain-boundaries'
SHARED_PROVIDERS = {
    'akamai.net', 'akamaihd.net', 'akamaiedge.net', 'akamaized.net',
    'akadns.net', 'edgesuite.net', 'edgekey.net', 'g.akamaiedge.net',
    'b.akamaiedge.net', 'amazonaws.com', 'cloudfront.net', 'cloudflare.com',
    'azureedge.net', 'azurefd.net', 'azurewebsites.net', 'cloudapp.net',
    'windows.net', 'blob.core.windows.net', 'sentry.io', 'intercom.io',
    'intercomcdn.com', 'optimizely.com', 'helpshift.com', 'localytics.com',
    'uservoice.com', 'segment.io', 'segment.com', 'fastly.net',
}
# Only reviewed scope/ordering findings can be waived. Invalid rules, unknown
# policies, arbitrary patterns and broken fallbacks always fail closed.
EXCEPTION_CODES = {'host-policy-overlap', 'host-option-overlap',
                   'cidr-policy-overlap', 'cidr-option-overlap',
                   'shared-provider-suffix', 'broad-cidr'}
BASE_LOCAL_NETWORKS = {
    '10.0.0.0/8', '127.0.0.0/8', '172.16.0.0/12', '192.168.0.0/16',
    '100.64.0.0/10', '169.254.0.0/16', '224.0.0.0/24',
    '::1/128', 'fc00::/7', 'fe80::/10',
}


def ascii_domain(value: str) -> str:
    return value.lower().encode('idna').decode('ascii')


@lru_cache(maxsize=1)
def domain_boundaries():
    """Load a hash-locked factual registry; no live DNS/network in validation."""
    metadata = json.loads((DATA / 'snapshot.json').read_text())
    for item in metadata['files']:
        if hashlib.sha256((DATA / item['path']).read_bytes()).hexdigest() != item['sha256']:
            raise ValueError(f"Domain-boundary snapshot hash mismatch: {item['path']}")
    tlds = {line.lower() for line in (DATA / 'tlds-alpha-by-domain.txt').read_text().splitlines()
            if line and not line.startswith('#')}
    rules, section = {}, None
    for line in (DATA / 'public_suffix_list.dat').read_text().splitlines():
        if '===BEGIN ICANN DOMAINS===' in line:
            section = 'icann'
        elif '===BEGIN PRIVATE DOMAINS===' in line:
            section = 'private'
        if not line or line.startswith('//'):
            continue
        prefix = '!' if line.startswith('!') else '*.' if line.startswith('*.') else ''
        rules[prefix + ascii_domain(line[len(prefix):])] = section
    brands = {item['tld'] for item in json.loads((DATA / 'brand-tlds.json').read_text())['entries']}
    if not brands <= tlds:
        raise ValueError('Brand allowlist contains a TLD absent from the IANA snapshot')
    return tlds, rules, brands


@lru_cache(maxsize=16384)
def public_suffix(value: str) -> tuple[str, str]:
    """Apply PSL exact, wildcard and exception semantics, retaining provenance."""
    _, rules, _ = domain_boundaries()
    labels = ascii_domain(value).split('.')
    matches = [(1, labels[-1], 'icann')]
    for i in range(len(labels)):
        suffix = '.'.join(labels[i:])
        if '!' + suffix in rules:
            return '.'.join(labels[i + 1:]), rules['!' + suffix]
        if suffix in rules:
            matches.append((len(labels) - i, suffix, rules[suffix]))
        if i > 0 and '*.' + suffix in rules:
            matches.append((len(labels) - i + 1, '.'.join(labels[i - 1:]), rules['*.' + suffix]))
    _, suffix, section = max(matches)
    return suffix, section


def registration_suffix(value: str) -> bool:
    _, _, brands = domain_boundaries()
    value = ascii_domain(value)
    suffix, section = public_suffix(value)
    return section == 'icann' and suffix == value and value not in brands


@lru_cache(maxsize=16384)
def shared_provider(value: str) -> bool:
    value = ascii_domain(value)
    _, rules, brands = domain_boundaries()
    if value in brands:
        return False
    suffix, section = public_suffix(value)
    # A parent of a PRIVATE PSL rule also captures the provider's tenant space.
    private_root = any(kind == 'private' and
                       (name.lstrip('!').removeprefix('*.') == value or
                        name.lstrip('!').removeprefix('*.').endswith('.' + value))
                       for name, kind in rules.items())
    return (value in SHARED_PROVIDERS or (suffix == value and section == 'private')
            or private_root or bool(re.fullmatch(
                r'(?:(?:execute-api|cognito-identity|mobileanalytics)\.)?[a-z]{2}(?:-gov)?-[a-z]+-\d\.amazonaws\.com'
                r'|s3[.-][a-z]{2}-[a-z]+-\d\.amazonaws\.com', value)))


def target(rule: Rule) -> dict:
    return {'kind': rule.kind, 'value': rule.value.lower(), 'policy': rule.policy,
            'options': sorted(rule.options)}


def location(rule: Rule) -> str:
    return f'{rule.file}:{rule.line}'


@dataclass
class Finding:
    code: str
    severity: str
    message: str
    targets: list[dict]
    locations: list[str]
    exception_reason: str | None = None


def finding(code, rules, message, severity='error'):
    return Finding(code, severity, message, [target(r) for r in rules], [location(r) for r in rules])


def suffix_matches(suffix: str, hostname: str) -> bool:
    suffix, hostname = suffix.lower(), hostname.lower()
    return hostname == suffix or hostname.endswith('.' + suffix)


def domain_matches(rule: Rule, hostname: str) -> bool:
    if rule.kind == 'host':
        return hostname.lower() == rule.value.lower()
    if rule.kind == 'host-suffix':
        return suffix_matches(rule.value, hostname)
    # Do not return a false "no conflict" for unsupported pattern languages.
    if rule.kind in {'host-keyword', 'host-wildcard'}:
        raise ValueError('Pattern matching is intentionally unsupported; use explicit owned destinations')
    return False


def overlap_code(left: Rule, right: Rule, kind: str) -> tuple[str, str]:
    if left.policy != right.policy:
        return kind + '-policy-overlap', 'error'
    if set(left.options) != set(right.options):
        return kind + '-option-overlap', 'error'
    return 'redundant-' + ('domain' if kind == 'host' else 'cidr'), 'info'


def audit_rules(rules: list[Rule], known_policies: set[str] | None = None) -> list[Finding]:
    findings, domains, ips, by_key = [], [], [], {}
    tlds, _, brands = domain_boundaries()
    if known_policies is not None:
        findings.extend(Finding('unknown-policy', 'error', d.message, [], [f'{d.file}:{d.line}'])
                        for d in validate_policy_references(rules, known_policies))
    for rule in rules:
        value = rule.value.lower()
        key = (rule.kind, value if rule.kind != 'user-agent' else rule.value)
        if key in by_key:
            old = by_key[key]
            if old.policy != rule.policy:
                code, severity = 'exact-policy-conflict', 'error'
            elif set(old.options) != set(rule.options):
                code, severity = 'exact-option-conflict', 'error'
            else:
                code, severity = 'exact-duplicate', 'error'
            findings.append(finding(code, [old, rule], 'One active target has multiple definitions.', severity))
        else:
            by_key[key] = rule
        if rule.kind in {'geoip', 'ip-asn', 'final'}:
            findings.append(finding('fallback-in-list', [rule], 'Reusable categories cannot own geography, ASN or final fallback.'))
        if rule.kind in {'host-keyword', 'host-wildcard', 'user-agent'}:
            code = {'host-keyword': 'broad-keyword', 'host-wildcard': 'unsupported-wildcard',
                    'user-agent': 'user-agent-routing'}[rule.kind]
            findings.append(finding(code, [rule], 'Curated categories require explicit destination ownership; patterns and User-Agent routing are not supported.'))
        if rule.kind in {'host', 'host-suffix'}:
            # Ordinary DNS names must have a currently delegated public TLD.
            if (value.split('.')[-1] not in tlds or '_' in value or
                    ('.' not in value and value not in brands)):
                findings.append(finding('invalid-public-domain', [rule], 'Destination is not a public hostname under the pinned IANA registry.'))
            if rule.kind == 'host-suffix':
                if registration_suffix(value):
                    findings.append(finding('public-suffix', [rule], 'Public registration suffix does not establish application ownership.'))
                elif shared_provider(value):
                    findings.append(finding('shared-provider-suffix', [rule], 'Provider-wide suffix captures unrelated tenants; require a reviewed dependency exception.'))
            domains.append(rule)
        if rule.kind in {'ip-cidr', 'ip6-cidr'}:
            try:
                network = ipaddress.ip_network(rule.value)
            except ValueError:
                findings.append(finding('invalid-rule', [rule], 'Malformed CIDR cannot be audited.'))
                continue
            ips.append((rule, network))
            if network.prefixlen < (24 if network.version == 4 else 48):
                findings.append(finding('broad-cidr', [rule], 'Large address range requires dated, authoritative service ownership evidence.'))
    for i, left in enumerate(domains):
        for right in domains[i + 1:]:
            if (left.kind, left.value.lower()) == (right.kind, right.value.lower()):
                continue
            if ((left.kind == 'host-suffix' and suffix_matches(left.value, right.value)) or
                    (right.kind == 'host-suffix' and suffix_matches(right.value, left.value))):
                code, severity = overlap_code(left, right, 'host')
                findings.append(finding(code, [left, right], 'Destination sets overlap; policy and DNS/interface options must be reviewed.', severity))
    for i, (left, left_net) in enumerate(ips):
        for right, right_net in ips[i + 1:]:
            if left_net.version != right_net.version or not left_net.overlaps(right_net):
                continue
            if (left.kind, left.value.lower()) == (right.kind, right.value.lower()):
                continue
            code, severity = overlap_code(left, right, 'cidr')
            findings.append(finding(code, [left, right], 'Address sets overlap; effective policy and options must be reviewed.', severity))
    return findings


def parse_sections(text: str) -> dict[str, list[str]]:
    result, section = {}, ''
    for raw in text.splitlines():
        line = raw.strip()
        if re.fullmatch(r'\[[a-z_]+\]', line):
            section = line
        elif line and not line.startswith(('#', ';', '//')):
            result.setdefault(section, []).append(line)
    return result


def audit_fallback(config: str, filename='Config/base.conf') -> list[Finding]:
    local = parse_sections(config).get('[filter_local]', [])
    normalize = lambda s: ', '.join(x.strip() for x in s.split(','))
    kinds = [s.split(',')[0].strip().lower() for s in local]
    if (kinds.count('geoip') != 1 or kinds.count('final') != 1 or
            [normalize(s) for s in local[-2:]] != ['geoip, cn, direct', 'final, Final']):
        return [Finding('config-fallback', 'error', 'Profile must end with exactly one GeoIP CN direct then Final.', [], [filename])]
    return []


def audit_profile(config: str, filename='<assembled>') -> list[Finding]:
    sections = parse_sections(config)
    findings = audit_fallback(config, filename)
    known = {line.split('=', 1)[1].split(',', 1)[0].strip()
             for line in sections.get('[policy]', []) if '=' in line}
    rules, diagnostics = inspect_text('\n'.join(sections.get('[filter_local]', [])), filename)
    findings.extend(Finding('invalid-rule', 'error', d.message, [], [f'{filename}:{d.line}'])
                    for d in diagnostics if d.severity == 'error')
    findings.extend(Finding('unknown-policy', 'error', d.message, [], [f'{filename}:{d.line}'])
                    for d in validate_policy_references(rules, known))
    return findings


def signature(code, targets):
    return code, tuple(sorted((t['kind'], t['value'].lower(), t['policy'], tuple(sorted(t['options'])))
                              for t in targets))


def narrower_first(targets: list[dict]) -> bool:
    if len(targets) != 2:
        return False
    first, second = targets
    if second['kind'] == 'host-suffix' and first['kind'] in {'host', 'host-suffix'}:
        return (suffix_matches(second['value'], first['value']) and
                (first['value'] != second['value'] or first['kind'] == 'host'))
    if first['kind'] in {'ip-cidr', 'ip6-cidr'} and first['kind'] == second['kind']:
        smaller, larger = ipaddress.ip_network(first['value']), ipaddress.ip_network(second['value'])
        return smaller != larger and smaller.subnet_of(larger)
    return False


def apply_exceptions(findings: list[Finding], document: dict) -> list[Finding]:
    """Bind exact kind/value/effective policy/options plus evidence and ordering."""
    exceptions, used, errors = {}, set(), []
    if (not isinstance(document, dict) or document.get('schema_version') != 2 or
            not isinstance(document.get('exceptions'), list)):
        return [Finding('exception-schema', 'error', 'Expected schema_version 2 and an exceptions array.', [], [])]
    for entry in document['exceptions']:
        try:
            targets = entry['targets']
            if (not isinstance(targets, list) or not targets or
                    any(not isinstance(t, dict) or set(t) != {'kind', 'value', 'policy', 'options'} or
                        not all(isinstance(t[k], str) and t[k] for k in ('kind', 'value', 'policy')) or
                        not isinstance(t['options'], list) or
                        not all(isinstance(option, str) for option in t['options'])
                        for t in targets)):
                raise ValueError('Exception targets require exact kind/value/policy and explicit options array')
            key = signature(entry['code'], targets)
            reason, evidence = entry['reason'].strip(), entry['evidence']
            if (entry['code'] not in EXCEPTION_CODES or not key[1] or not reason or key in exceptions or
                    not isinstance(evidence, list) or not evidence or
                    not all(isinstance(url, str) and url.startswith('https://') for url in evidence)):
                raise ValueError('Exception needs a permitted code, exact unique targets, reason and HTTPS evidence')
            if entry['code'].endswith('-overlap') and entry.get('ordering') != 'narrower-before-broader':
                raise ValueError('Overlap exception must require narrower-before-broader ordering')
            exceptions[key] = entry
        except (KeyError, TypeError, ValueError, AttributeError) as exc:
            errors.append(Finding('exception-schema', 'error', str(exc), [], []))
    for item in findings:
        key = signature(item.code, item.targets)
        if key in exceptions:
            used.add(key)
            if item.code.endswith('-overlap') and not narrower_first(item.targets):
                errors.append(Finding('exception-order', 'error', 'Reviewed override must precede its broader rule in the assembled order.', item.targets, item.locations))
                continue
            item.exception_reason = exceptions[key]['reason']
            item.severity = 'accepted'
    for code, targets in exceptions.keys() - used:
        errors.append(Finding('stale-exception', 'error', 'Exception no longer matches a current finding.',
                              [dict(zip(('kind', 'value', 'policy', 'options'), t)) for t in targets], []))
    return errors


def deduplicate_findings(findings):
    result, seen = [], set()
    for item in findings:
        key = (signature(item.code, item.targets), tuple(item.locations), item.message)
        if key not in seen:
            seen.add(key)
            result.append(item)
    return result


def audit_ip_evidence(text: str, path: str) -> list[Finding]:
    """Require a dated source for every address leaf, including single IPs."""
    source = re.search(r'^# Official source: (https://\S+)\s*$', text, re.M)
    retrieved = re.search(r'^# Retrieved (\d{4}-\d{2}-\d{2}); SHA-256: ([0-9a-f]{64})\s*$', text, re.M)
    try:
        if not source or not retrieved:
            raise ValueError('missing official source URL or dated source hash')
        date.fromisoformat(retrieved[1])
    except ValueError as exc:
        return [Finding('ip-evidence', 'error', f'Address leaf requires reviewable ownership evidence: {exc}.', [], [path])]
    return []


def audit_repository(root: Path = ROOT) -> tuple[list[Rule], list[Finding]]:
    # Lazy import keeps build_config.private_scope_errors free to reuse this module.
    from build_config import BASE, build, load_categories, policy_names, sections
    findings, enabled_rules = [], []
    try:
        domain_boundaries()
        defaults = load_categories(root=root)
        categories = json.loads((root / 'Config/categories.json').read_text())
        known = policy_names(sections((root / 'Config/base.conf').read_text()))
    except (OSError, ValueError, KeyError, TypeError) as exc:
        return [], [Finding('repository-input', 'error', str(exc), [], [])]
    listed = {item['path'] for item in categories}
    actual = {str(path.relative_to(root)) for path in (root / 'Rules').rglob('*.list')}
    if listed != actual:
        findings.append(Finding('category-inventory', 'error', 'Every rule leaf must be declared exactly once, including optional leaves.', [], sorted(listed ^ actual)))
    rule_sets = {}
    for item in categories:
        path = item['path']
        source_text = (root / path).read_text()
        parsed, diagnostics = inspect_text(source_text, path)
        if path.startswith('Rules/IP/'):
            findings.extend(audit_ip_evidence(source_text, path))
        findings.extend(Finding('invalid-rule', 'error', d.message, [], [f'{path}:{d.line}'])
                        for d in diagnostics if d.severity == 'error')
        for rule in parsed:
            if rule.kind in {'ip-cidr', 'ip6-cidr'} and not path.startswith('Rules/IP/'):
                findings.append(finding('ip-in-domain-category', [rule], 'Address rules require a separate Rules/IP leaf and ownership evidence.'))
            elif path.startswith('Rules/IP/') and rule.kind not in {'ip-cidr', 'ip6-cidr'}:
                findings.append(finding('domain-in-ip-category', [rule], 'IP leaves must contain address ranges only.'))
        rule_sets[path] = [Rule(r.file, r.line, r.kind, r.value, item['policy'], r.options) for r in parsed]
    enabled_rules = [r for item in defaults for r in rule_sets[item['path']]]
    base_text = (root / 'Config/base.conf').read_text()
    base_rules, _ = inspect_text('\n'.join(parse_sections(base_text).get('[filter_local]', [])), 'Config/base.conf')
    findings.extend(audit_profile(base_text, 'Config/base.conf'))
    base_extras = []
    for rule in base_rules:
        if rule.kind in {'geoip', 'final'}:
            continue
        if (rule.kind in {'ip-cidr', 'ip6-cidr'} and rule.value in BASE_LOCAL_NETWORKS
                and rule.policy == 'direct' and not rule.options):
            continue
        if rule.kind in {'ip-cidr', 'ip6-cidr'}:
            findings.append(finding('unsafe-base-address', [rule], 'Public or modified base IP routes require a reviewed Rules/IP category.'))
        base_extras.append(rule)
    # Defaults are audited as actually assembled; each disabled leaf is also
    # audited with defaults so optional lists cannot conceal incompatible rules.
    variants = [([], [], defaults)]
    disabled_tags = []
    for optional in categories:
        if optional not in defaults:
            disabled_tags.append(optional['tag'])
            variants.append(([optional['tag']], [], load_categories(enable=[optional['tag']], root=root)))
    if len(disabled_tags) > 1:
        variants.append((disabled_tags, [], load_categories(enable=disabled_tags, root=root)))
    enabled_optional_tags = [item['tag'] for item in defaults if item['path'].startswith('Rules/Optional/')]
    for tag in enabled_optional_tags:
        variants.append(([], [tag], load_categories(disable=[tag], root=root)))
    if len(enabled_optional_tags) > 1:
        variants.append(([], enabled_optional_tags, load_categories(disable=enabled_optional_tags, root=root)))
    for enable, disable, items in variants:
        rules = [r for item in items for r in rule_sets[item['path']]]
        domain_rules = [r for r in rules if r.kind not in {'ip-cidr', 'ip6-cidr'}]
        address_rules = [r for r in rules if r.kind in {'ip-cidr', 'ip6-cidr'}]
        if not any(f.code == 'invalid-rule' for f in findings):
            findings.extend(audit_rules(domain_rules + base_extras + address_rules, known))
        label = ('default' if not enable and not disable else
                 ('enable=' + ','.join(enable) if enable else 'disable=' + ','.join(disable)))
        try:
            standalone = build('standalone', enable=enable, disable=disable, root=root)
            remote = build('remote', enable=enable, disable=disable, root=root)
        except (OSError, ValueError, KeyError, TypeError) as exc:
            findings.append(Finding('profile-build', 'error', str(exc), [], [label]))
            continue
        findings.extend(audit_profile(standalone, f'assembled/{label}/standalone'))
        findings.extend(audit_profile(remote, f'assembled/{label}/remote'))
        expected_remote = [f"{BASE}master/{item['path']}, tag={item['tag']}, force-policy={item['policy']}, update-interval=86400, opt-parser=false, enabled=true" for item in items]
        if parse_sections(remote).get('[filter_remote]', []) != expected_remote:
            findings.append(Finding('remote-manifest', 'error', 'Remote resources differ from the selected owned category manifest.', [], [label]))
        if parse_sections(standalone).get('[filter_remote]', []):
            findings.append(Finding('standalone-remote', 'error', 'Standalone profile unexpectedly imports remote routing resources.', [], [label]))
        compiled_rules, _ = inspect_text('\n'.join(parse_sections(standalone)['[filter_local]']))
        canonical = lambda rs: [signature('rule', [target(r)]) for r in rs]
        expected = domain_rules + base_rules[:-2] + address_rules + base_rules[-2:]
        if canonical(compiled_rules) != canonical(expected):
            findings.append(Finding('standalone-manifest', 'error', 'Standalone rule order, effective policies or options differ from domain/base-IP/service-IP/fallback order.', [], [label]))
        if not enable and not disable:
            published = root / 'Config/quantumult-x.conf'
            if not published.exists() or published.read_text() != remote:
                findings.append(Finding('generated-config-drift', 'error', 'Committed public profile is not the current default remote build.', [], ['Config/quantumult-x.conf']))
    findings = deduplicate_findings(findings)
    exception_path = root / 'docs/semantic-exceptions.json'
    if exception_path.exists():
        try:
            findings.extend(apply_exceptions(findings, json.loads(exception_path.read_text())))
        except (OSError, ValueError) as exc:
            findings.append(Finding('exception-schema', 'error', str(exc), [], ['docs/semantic-exceptions.json']))
    return enabled_rules, findings


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--json', action='store_true')
    args = parser.parse_args(argv)
    rules, findings = audit_repository()
    counts = Counter(f.severity for f in findings)
    if args.json:
        print(json.dumps({'active_rules': len(rules), 'counts': dict(counts),
                          'findings': [asdict(f) for f in findings]}, indent=2, ensure_ascii=False))
    else:
        for item in findings:
            if item.severity == 'error':
                print(f"error [{item.code}] {', '.join(item.locations)}: {item.message}")
        print(f'Audited {len(rules)} default rules and each optional category: ' + ', '.join(f'{n} {k}' for k, n in sorted(counts.items())))
        print('Offline boundary audit; not a QX engine, reachability test, or proof of complete coverage.')
    return int(bool(counts['error']))


if __name__ == '__main__':
    raise SystemExit(main())
