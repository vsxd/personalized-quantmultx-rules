"""Routing scope, assembled fallback and exception regression checks."""
import importlib.util
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('semantic_auditor', ROOT / 'scripts/audit_semantics.py')
audit = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = audit
spec.loader.exec_module(audit)
from build_config import build


def parse(text):
    rules, diagnostics = audit.inspect_text(text)
    if any(d.severity == 'error' for d in diagnostics):
        raise AssertionError(diagnostics)
    return rules


def codes(text):
    return {f.code for f in audit.audit_rules(parse(text)) if f.severity == 'error'}


def exception(rules, code='host-policy-overlap'):
    return {'schema_version': 2, 'exceptions': [{
        'code': code, 'targets': [audit.target(r) for r in rules],
        'reason': 'Verified narrower dependency must use its own policy.',
        'evidence': ['https://help.openai.com/en/articles/9247338'],
        'ordering': 'narrower-before-broader'}]}


class SemanticAuditTest(unittest.TestCase):
    def test_suffix_boundaries_do_not_capture_lookalikes(self):
        rule = parse('host-suffix, hsbc.com.hk, direct')[0]
        for host in ('hsbc.com.hk', 'www.personal.hsbc.com.hk'):
            self.assertTrue(audit.domain_matches(rule, host))
        for host in ('not-hsbc.com.hk', 'hsbc.com.hk.example.com'):
            self.assertFalse(audit.domain_matches(rule, host))

    def test_host_and_suffix_parent_child_are_compared(self):
        text = 'host, humb.apple.com, AI-Dependencies\nhost-suffix, apple.com, Apple'
        self.assertIn('host-policy-overlap', codes(text))
        self.assertIn('host-policy-overlap', codes(text.replace('host, humb', 'host-suffix, humb')))
        self.assertIn('host-policy-overlap', codes('host, example.com, direct\nhost-suffix, example.com, Global'))

    def test_exact_target_conflicts_include_dns_and_interface_options(self):
        self.assertIn('exact-policy-conflict', codes('host, example.com, direct\nhost, example.com, Global'))
        self.assertIn('exact-option-conflict', codes(
            'host, example.com, direct\nhost, example.com, direct, force-remote-dns'))
        self.assertIn('exact-option-conflict', codes(
            'host, example.com, direct, via-interface=en0\nhost, example.com, direct, via-interface=en1'))

    def test_overlapping_same_policy_options_change_behavior(self):
        self.assertIn('host-option-overlap', codes(
            'host, api.example.com, direct, force-remote-dns\nhost-suffix, example.com, direct'))
        self.assertIn('cidr-option-overlap', codes(
            'ip-cidr, 192.0.2.1/32, direct, via-interface=en0\nip-cidr, 192.0.2.0/24, direct'))

    def test_ip_intersections_compare_address_sets(self):
        self.assertIn('cidr-policy-overlap', codes(
            'ip-cidr, 23.211.15.99/32, China\nip-cidr, 23.211.15.0/24, Global'))
        self.assertIn('cidr-policy-overlap', codes(
            'ip6-cidr, 2001:db8::1/128, China\nip6-cidr, 2001:db8::/48, Global'))
        self.assertNotIn('cidr-policy-overlap', codes(
            'ip-cidr, 192.0.2.0/24, China\nip-cidr, 198.51.100.0/24, Global'))

    def test_arbitrary_patterns_cannot_silently_pass_without_a_witness(self):
        for value in ('apple.*', 'init*.push.apple.com', '*-content.icloud.com.cn', 'a*b.example.com'):
            self.assertIn('unsupported-wildcard', codes(f'host-wildcard, {value}, Apple'))
        self.assertIn('broad-keyword', codes('host-keyword, google, Google'))
        self.assertIn('user-agent-routing', codes('user-agent, AdBlock*, Global'))
        with self.assertRaises(ValueError):
            audit.domain_matches(parse('host-wildcard, *.example.com, direct')[0], 'api.example.com')

    def test_registration_boundaries_use_full_pinned_psl(self):
        for suffix in ('cn', 'com', 'co.nz', 'com.ar', 'co.uk', 'a.ck'):
            self.assertIn('public-suffix', codes(f'host-suffix, {suffix}, Global'), suffix)
        for domain in ('example.co.nz', 'example.com.ar', 'www.ck'):
            self.assertNotIn('public-suffix', codes(f'host-suffix, {domain}, Global'), domain)
        self.assertEqual(('ck', 'icann'), audit.public_suffix('www.ck'))

    def test_verified_brand_tlds_are_not_country_or_registration_suffixes(self):
        for domain in ('apple', 'google', 'microsoft'):
            self.assertFalse(codes(f'host-suffix, {domain}, Global'), domain)
        self.assertIn('public-suffix', codes('host-suffix, bank, Global'))

    def test_invalid_or_internal_domains_do_not_enter_public_corpus(self):
        for domain in ('iqiyi.demo.uwp', 'cbs', 'localnetwork.uop',
                       'onecollector.cloudapp.aria', 'img-prod-cms-rt-microsoft-com',
                       'evoke-windowsservices-tas.msedge', '_service.example.com'):
            self.assertIn('invalid-public-domain', codes(f'host-suffix, {domain}, Global'), domain)
        self.assertNotIn('invalid-public-domain', codes('host-suffix, example.xn--fiqs8s, China'))

    def test_shared_providers_and_psl_tenants_have_distinct_boundaries(self):
        for value in ('akadns.net', 'edgesuite.net', 'windows.net', 'us-west-2.amazonaws.com',
                      'execute-api.us-east-1.amazonaws.com', 's3-ap-southeast-1.amazonaws.com',
                      'github.io', 's3.amazonaws.com', 'cloudfront.net'):
            self.assertIn('shared-provider-suffix', codes(f'host-suffix, {value}, Global'), value)
        for value in ('hsbc.edge.sdk.awswaf.com', 'chatgpt-prod.aks.azure.com'):
            self.assertNotIn('shared-provider-suffix', codes(f'host, {value}, direct'), value)
        self.assertNotIn('shared-provider-suffix', codes('host-suffix, team.github.io, Global'))

    def test_only_profile_tail_owns_fallback(self):
        for line in ('geoip, cn, China', 'final, Global', 'ip-asn, 4134, China'):
            self.assertIn('fallback-in-list', codes(line))
        self.assertFalse(audit.audit_fallback('[filter_local]\nip-cidr, 10.0.0.0/8, direct\ngeoip, cn, direct\nfinal, Final'))
        for suffix in ('geoip, cn, direct\ngeoip, cn, China\nfinal, Final',
                       'geoip, cn, direct\nhost, example.com, Global\nfinal, Final',
                       'geoip, cn, direct, force-cellular\nfinal, Final'):
            self.assertTrue(audit.audit_fallback('[filter_local]\n' + suffix))

    def test_assembled_profile_requires_known_policies(self):
        config = '[policy]\nstatic = Final, proxy\n[filter_local]\nhost, example.com, Missing\ngeoip, cn, direct\nfinal, Final'
        self.assertIn('unknown-policy', {f.code for f in audit.audit_profile(config)})
        self.assertNotIn('unknown-policy', {f.code for f in audit.audit_profile(config.replace('Missing', 'Final'))})

    def test_exception_binds_exact_options_evidence_and_effective_policy(self):
        rules = parse('host, humb.apple.com, AI-Dependencies\nhost-suffix, apple.com, Apple')
        findings, document = audit.audit_rules(rules), exception(rules)
        self.assertEqual([], audit.apply_exceptions(findings, document))
        self.assertEqual('accepted', findings[0].severity)
        changed = parse('host, humb.apple.com, AI-Dependencies, force-remote-dns\nhost-suffix, apple.com, Apple')
        self.assertIn('stale-exception', {f.code for f in audit.apply_exceptions(audit.audit_rules(changed), document)})
        document['exceptions'][0]['evidence'] = []
        self.assertIn('exception-schema', {f.code for f in audit.apply_exceptions(audit.audit_rules(rules), document)})

    def test_exception_enforces_narrower_before_broader(self):
        rules = parse('host, humb.apple.com, AI-Dependencies\nhost-suffix, apple.com, Apple')
        findings = audit.audit_rules(list(reversed(rules)))
        self.assertIn('exception-order', {f.code for f in audit.apply_exceptions(findings, exception(rules))})
        self.assertEqual('error', findings[0].severity)

    def test_invalid_and_structural_errors_cannot_be_waived(self):
        for text, code in [('host-keyword, apple, Apple', 'broad-keyword'),
                           ('host-suffix, cn, China', 'public-suffix'),
                           ('geoip, cn, direct', 'fallback-in-list')]:
            rules = parse(text)
            findings = audit.audit_rules(rules)
            errors = audit.apply_exceptions(findings, exception(rules, code))
            self.assertIn('exception-schema', {f.code for f in errors})
            self.assertIn('error', {f.severity for f in findings})

    def test_missing_options_cannot_implicitly_waive_future_behavior(self):
        rules = parse('host-suffix, intercom.io, AI-Dependencies')
        document = exception(rules, 'shared-provider-suffix')
        del document['exceptions'][0]['targets'][0]['options']
        self.assertIn('exception-schema', {f.code for f in audit.apply_exceptions(audit.audit_rules(rules), document)})

    def test_redundant_same_behavior_is_visible(self):
        findings = audit.audit_rules(parse('ip-cidr, 192.0.2.0/24, Global\nip-cidr, 192.0.2.1/32, Global'))
        self.assertEqual(['redundant-cidr'], [f.code for f in findings])
        self.assertEqual('info', findings[0].severity)

    def test_every_ip_leaf_needs_dated_authoritative_source_even_for_one_ip(self):
        path = 'Rules/IP/Service.list'
        self.assertTrue(audit.audit_ip_evidence('ip-cidr, 192.0.2.1/32, Global', path))
        header = ('# Official source: https://core.telegram.org/resources/cidr.txt\n'
                  '# Retrieved 2026-10-14; SHA-256: ' + 'a' * 64 + '\n')
        self.assertFalse(audit.audit_ip_evidence(header, path))
        self.assertTrue(audit.audit_ip_evidence(header.replace('2026-10-14', '2026-13-14'), path))

    def test_active_repository_has_no_unreviewed_semantic_errors(self):
        _, findings = audit.audit_repository()
        errors = [f'{f.code}: {f.locations}: {f.message}' for f in findings if f.severity == 'error']
        self.assertEqual([], errors, '\n'.join(errors))


class ManifestSelectionTest(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        for dirname in ('Config', 'Rules/Services', 'Rules/Optional'):
            (self.root / dirname).mkdir(parents=True)
        (self.root / 'Config/base.conf').write_text(
            '[policy]\nstatic = Service, direct\nstatic = Optional, proxy\nstatic = Final, proxy\n'
            '[filter_remote]\n[filter_local]\ngeoip, cn, direct\nfinal, Final\n')
        (self.root / 'Rules/Services/Core.list').write_text('host-suffix, example.com, Service\n')
        (self.root / 'Rules/Optional/Dependency.list').write_text('host-suffix, example.org, Optional\n')
        self.categories = [
            {'path': 'Rules/Services/Core.list', 'tag': 'Core', 'policy': 'Service', 'default_enabled': True},
            {'path': 'Rules/Optional/Dependency.list', 'tag': 'Dependency', 'policy': 'Optional', 'default_enabled': True}]

    def audit(self):
        (self.root / 'Config/categories.json').write_text(json.dumps(self.categories))
        (self.root / 'Config/quantumult-x.conf').write_text(build(root=self.root))
        return audit.audit_repository(self.root)

    def test_optional_folder_does_not_hide_default_enabled_dependency(self):
        rules, findings = self.audit()
        self.assertEqual(2, len(rules))
        self.assertFalse([f for f in findings if f.severity == 'error'])

    def test_disabled_leaf_is_audited_without_polluting_default_count(self):
        self.categories[1]['default_enabled'] = False
        (self.root / 'Rules/Optional/Dependency.list').write_text('host, www.example.com, Optional\n')
        rules, findings = self.audit()
        self.assertEqual(1, len(rules))
        self.assertIn('host-policy-overlap', {f.code for f in findings})

    def test_disabled_leaf_invalid_domain_remains_an_error(self):
        self.categories[1]['default_enabled'] = False
        (self.root / 'Rules/Optional/Dependency.list').write_text('host, service.invalid, Optional\n')
        _, findings = self.audit()
        self.assertIn('invalid-public-domain', {f.code for f in findings})

    def test_undeclared_leaf_is_not_silently_ignored(self):
        (self.root / 'Rules/Optional/Hidden.list').write_text('host, example.net, direct\n')
        _, findings = self.audit()
        self.assertIn('category-inventory', {f.code for f in findings})

    def test_stale_published_profile_fails_even_if_builder_itself_works(self):
        self.audit()
        (self.root / 'Config/quantumult-x.conf').write_text('stale')
        _, findings = audit.audit_repository(self.root)
        self.assertIn('generated-config-drift', {f.code for f in findings})

    def test_conflicts_between_two_disabled_leaves_are_checked_together(self):
        self.categories[1]['default_enabled'] = False
        (self.root / 'Rules/Optional/Second.list').write_text('host, api.example.org, Service\n')
        self.categories.append({'path': 'Rules/Optional/Second.list', 'tag': 'Second',
                                'policy': 'Service', 'default_enabled': False})
        _, findings = self.audit()
        self.assertIn('host-policy-overlap', {f.code for f in findings})

    def test_base_local_domain_cannot_evade_service_boundary_checks(self):
        base = self.root / 'Config/base.conf'
        base.write_text(base.read_text().replace('geoip, cn, direct',
                        'host, api.example.com, Optional\ngeoip, cn, direct'))
        _, findings = self.audit()
        self.assertIn('host-policy-overlap', {f.code for f in findings})

    def test_actual_compiled_order_is_checked_not_only_the_manifest(self):
        self.audit()
        original_build = build

        def broken_builder(mode='remote', **kwargs):
            text = original_build(mode, **kwargs)
            if mode == 'standalone':
                before = 'host-suffix, example.com, Service\nhost-suffix, example.org, Optional'
                text = text.replace(before, '\n'.join(reversed(before.splitlines())))
            return text

        with patch('build_config.build', side_effect=broken_builder):
            _, findings = audit.audit_repository(self.root)
        self.assertIn('standalone-manifest', {f.code for f in findings})


if __name__ == '__main__':
    unittest.main()
