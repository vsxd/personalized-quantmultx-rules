#!/usr/bin/env python3
"""Build reviewed QX profiles from one category manifest; never fetch or publish secrets."""
from __future__ import annotations

import argparse
import ipaddress
import json
import os
from pathlib import Path, PurePosixPath
import re
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'scripts'))
from validate_rules import Rule, inspect_text, validate_policy_references

BASE = 'https://raw.githubusercontent.com/vsxd/personalized-quantmultx-rules/'
BUILTINS = {'direct', 'proxy', 'reject'}


def sections(text: str) -> dict[str, list[str]]:
    result: dict[str, list[str]] = {}
    current = ''
    for line in text.splitlines():
        if re.fullmatch(r'\[[a-z_]+\]', line.strip()):
            current = line.strip()
            result.setdefault(current, [])
        else:
            result.setdefault(current, []).append(line)
    return result


def active(lines: list[str]) -> list[str]:
    return [s.strip() for s in lines if s.strip() and not s.lstrip().startswith(('#', ';', '//'))]


def policy_names(config: dict[str, list[str]]) -> set[str]:
    return BUILTINS | {line.split('=', 1)[1].split(',', 1)[0].strip()
                       for line in active(config['[policy]'])}


def load_categories(enable=(), disable=(), root=ROOT) -> list[dict]:
    """Validate every declaration, then select defaults plus explicit tag overrides."""
    items = json.loads((root / 'Config/categories.json').read_text())
    if not isinstance(items, list) or not items:
        raise ValueError('Category manifest must be a nonempty array')
    tags, paths, group_policies = set(), set(), {}
    known = policy_names(sections((root / 'Config/base.conf').read_text()))
    for item in items:
        path, tag, policy = item['path'], item['tag'], item['policy']
        parsed_path = PurePosixPath(path)
        if (not path.startswith('Rules/') or not path.endswith('.list')
                or not re.fullmatch(r'[A-Za-z0-9_./-]+', path) or str(parsed_path) != path
                or '..' in parsed_path.parts or '\\' in path
                or not (root / path).resolve().is_relative_to((root / 'Rules').resolve())):
            raise ValueError(f'Invalid owned rule path: {path!r}')
        if not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9._-]*', tag):
            raise ValueError(f'Invalid category tag: {tag!r}')
        if tag in tags or path in paths:
            raise ValueError(f'Duplicate category tag or path: {tag}: {path}')
        if policy not in known:
            raise ValueError(f'Unknown category policy: {policy}')
        if not isinstance(item.get('default_enabled', True), bool):
            raise ValueError(f'default_enabled must be boolean: {tag}')
        if not (root / path).is_file():
            raise ValueError(f'Missing owned list: {path}')
        if 'remote_group' in item:
            group = item['remote_group']
            if not isinstance(group, str) or not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_-]*', group):
                raise ValueError(f'Invalid remote group: {group!r}')
            if path.startswith(('Rules/Optional/', 'Rules/IP/')) or not item.get('default_enabled', True):
                raise ValueError(f'Optional and IP resources must remain individually selectable: {tag}')
            if group in group_policies and group_policies[group] != policy:
                raise ValueError(f'Remote group {group} mixes effective policies')
            group_policies[group] = policy
        tags.add(tag)
        paths.add(path)
    if tags & {f'Common-{group}' for group in group_policies}:
        raise ValueError('Remote bundle tag conflicts with a category tag')
    enable, disable = set(enable), set(disable)
    if enable & disable or (enable | disable) - tags:
        raise ValueError('Enable/disable tags must exist and must not contradict one another')
    return [item for item in items if item['tag'] not in disable
            and (item.get('default_enabled', True) or item['tag'] in enable)]


def remote_resources(items, root=ROOT):
    """Coalesce complete default groups; retain leaves for custom selections.

    The first selected member fixes the bundle position. source_paths records
    the ordered leaf contents, so auditors can verify coverage and precedence.
    A group with even one disabled member cannot use the published full bundle.
    """
    defaults = load_categories(root=root)
    members, selected = {}, {}
    for item in defaults:
        if group := item.get('remote_group'):
            members.setdefault(group, []).append(item['path'])
    for item in items:
        if group := item.get('remote_group'):
            selected.setdefault(group, []).append(item['path'])
    complete = {group for group, paths in selected.items() if paths == members.get(group)}
    result, emitted = [], set()
    for item in items:
        group = item.get('remote_group')
        if group in complete:
            if group in emitted:
                continue
            emitted.add(group)
            result.append({'path': f'Bundles/{group}.list', 'tag': f'Common-{group}',
                           'policy': item['policy'], 'source_paths': members[group].copy()})
        else:
            result.append({key: item[key] for key in ('path', 'tag', 'policy')}
                          | {'source_paths': [item['path']]})
    return result


def category_rules(item, root=ROOT, known=None):
    """Parse a leaf and validate its effective policy without changing it."""
    if known is None:
        known = policy_names(sections((root / 'Config/base.conf').read_text()))
    rules, diagnostics = inspect_text((root / item['path']).read_text(), item['path'])
    diagnostics += validate_policy_references(rules, known, {item['path']: item['policy']})
    errors = [d.message for d in diagnostics if d.severity == 'error']
    if any(r.kind in {'geoip', 'ip-asn', 'final'} for r in rules):
        errors.append('GeoIP, ASN and Final are forbidden in reusable categories')
    if errors:
        raise ValueError(f"Invalid category {item['path']}: " + '; '.join(errors))
    return [Rule(r.file, r.line, r.kind, r.value, item['policy'], r.options) for r in rules]


def serialize(rule, policy=None):
    return ', '.join((rule.kind, rule.value, policy or rule.policy, *rule.options))


def semantic_key(rule):
    value = (str(ipaddress.ip_network(rule.value)) if rule.kind in {'ip-cidr', 'ip6-cidr'}
             else rule.value.lower())
    return rule.kind, value, rule.policy, tuple(sorted(rule.options))


def private_conflict_errors(private_rules, effective_rules):
    """Only new private-involving conflicts; public exceptions remain public."""
    from audit_semantics import suffix_matches
    errors = []
    domain_types, address_types = {'host', 'host-suffix'}, {'ip-cidr', 'ip6-cidr'}
    for i, left in enumerate(private_rules):
        for right in private_rules[i + 1:] + effective_rules:
            if left.policy == right.policy and set(left.options) == set(right.options):
                continue
            overlap = False
            if left.kind in domain_types and right.kind in domain_types:
                overlap = (left.value.lower() == right.value.lower()
                           or (left.kind == 'host-suffix' and suffix_matches(left.value, right.value))
                           or (right.kind == 'host-suffix' and suffix_matches(right.value, left.value)))
            elif left.kind in address_types and right.kind in address_types:
                first, second = ipaddress.ip_network(left.value), ipaddress.ip_network(right.value)
                overlap = first.version == second.version and first.overlaps(second)
            if overlap:
                errors.append(f'{left.file}:{left.line}: overlapping policy/options conflict with '
                              f'{right.file}:{right.line}; resolve the explicit routing choice before inheritance')
    return errors


def private_scope_errors(rules):
    """Private intranet names are allowed; broad app/provider/IP capture is not inherited silently."""
    from audit_semantics import registration_suffix, shared_provider
    errors = []
    for rule in rules:
        reason = None
        if rule.kind not in {'host', 'host-suffix', 'ip-cidr', 'ip6-cidr'}:
            reason = 'only explicit host/suffix or reviewed IP overrides can be inherited'
        elif rule.kind == 'host-suffix':
            if '.' not in rule.value or registration_suffix(rule.value) or shared_provider(rule.value):
                reason = 'registration or shared-provider suffix is too broad for automatic inheritance'
        elif rule.kind in {'ip-cidr', 'ip6-cidr'}:
            network = ipaddress.ip_network(rule.value)
            if network.prefixlen < (24 if network.version == 4 else 48):
                reason = 'large inherited IP range needs an explicit scope review'
        if reason:
            errors.append(f'{rule.file}:{rule.line}: {reason}')
    return errors


def build(mode='remote', ref='master', private_text=None, enable=(), disable=(), root=ROOT):
    if mode not in {'remote', 'standalone'}:
        raise ValueError('mode must be remote or standalone')
    if not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9._/-]*', ref) or '..' in ref.split('/'):
        raise ValueError('ref must be a Git revision, not a URL or arbitrary text')
    config = sections((root / 'Config/base.conf').read_text())
    categories = load_categories(enable, disable, root)
    known = policy_names(config)
    domain_lines, address_lines, effective_rules = [], [], []
    for item in categories:
        rules = category_rules(item, root, known)
        effective_rules.extend(rules)
        if mode == 'standalone':
            for rule in rules:
                destination = address_lines if rule.kind in {'ip-cidr', 'ip6-cidr'} else domain_lines
                destination.append(serialize(rule))
    if mode == 'remote':
        for resource in remote_resources(categories, root):
            config['[filter_remote]'].append(
                f"{BASE}{ref}/{resource['path']}, tag={resource['tag']}, force-policy={resource['policy']}, "
                'update-interval=86400, opt-parser=false, enabled=true')

    local = active(config['[filter_local]'])
    if local[-2:] != ['geoip, cn, direct', 'final, Final']:
        raise ValueError('Base config must end with GeoIP CN direct then Final')
    if sum(l.split(',')[0].strip().lower() in {'geoip', 'final'} for l in local) != 2:
        raise ValueError('Base config contains duplicate fallback rules')

    private_rules = []
    if private_text is not None:
        private = sections(private_text)
        for key in ('[server_remote]', '[server_local]'):
            config[key] = private.get(key, []).copy()
        for line in active(config['[server_local]']):
            tag = re.search(r'(?:^|,)\s*tag\s*=\s*([^,]+)', line)
            if tag:
                known.add(tag.group(1).strip())
        inherited = []
        base_rules, _ = inspect_text('\n'.join(local[:-2]), 'base filter_local')
        existing_rules = effective_rules + base_rules
        existing_keys = {semantic_key(rule) for rule in existing_rules}
        for line in active(private.get('[filter_local]', [])):
            if line.split(',')[0].strip().lower() in {'final', 'geoip', 'geoip6'}:
                continue
            inherited.append(line)
        if inherited:
            rules, diagnostics = inspect_text('\n'.join(inherited), 'private filter_local')
            diagnostics += validate_policy_references(rules, known)
            errors = [f'{d.file}:{d.line}: {d.message}' for d in diagnostics if d.severity == 'error']
            if not errors:
                # Identical effective routes need no private override, including
                # benign canonicalized copies of the base's private IP ranges.
                rules = [r for r in rules if semantic_key(r) not in existing_keys]
                errors += private_scope_errors(rules)
                errors += private_conflict_errors(rules, existing_rules)
            if errors:
                raise ValueError('Private overrides need review; no output generated:\n' + '\n'.join(errors)
                                 + '\nCustom groups and remote node tags are not inherited implicitly.')
            private_rules = list(dict.fromkeys(serialize(r) for r in rules))
    config['[filter_local]'] = (private_rules + domain_lines + local[:-2]
                                 + address_lines + local[-2:])
    return '\n'.join((key + '\n' if key else '') + '\n'.join(lines).rstrip() + '\n'
                     for key, lines in config.items())


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--mode', choices=('remote', 'standalone'), default='remote')
    parser.add_argument('--ref', default='master')
    parser.add_argument('--enable', action='append', default=[], metavar='TAG')
    parser.add_argument('--disable', action='append', default=[], metavar='TAG')
    parser.add_argument('--private-from', type=Path,
                        help='Import only server sections and reviewed non-final local overrides')
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    if args.private_from and args.output.resolve().is_relative_to(ROOT):
        parser.error('Private output must stay outside the repository')
    content = build(args.mode, args.ref, args.private_from.read_text() if args.private_from else None,
                    args.enable, args.disable)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    # Atomic replacement: never truncate an existing profile on a failed write.
    temp_path = None
    try:
        with tempfile.NamedTemporaryFile(mode='w', encoding='utf-8', dir=args.output.parent,
                                         prefix='.qx-build-', delete=False) as handle:
            temp_path = Path(handle.name)
            os.fchmod(handle.fileno(), 0o600 if args.private_from else 0o644)
            handle.write(content)
        os.replace(temp_path, args.output)
    finally:
        if temp_path is not None:
            temp_path.unlink(missing_ok=True)
    print(f'Built {args.mode} profile: {args.output} (private={bool(args.private_from)})')


if __name__ == '__main__':
    main()
