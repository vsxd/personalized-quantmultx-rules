"""Destination ownership contracts and negative controls for the published corpus."""
import json
from pathlib import Path
import sys
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path[:0] = [str(ROOT / 'scripts'), str(ROOT / 'tests')]
from validate_rules import inspect_text
import build_config
from test_service_coverage import covering_rules, first_hostname_policy


class RepositoryCategoriesTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.categories = json.loads((ROOT / 'Config/categories.json').read_text())
        cls.rules = {}
        for item in cls.categories:
            cls.rules[item['tag']], diagnostics = inspect_text((ROOT / item['path']).read_text(), item['path'])
            if any(d.severity == 'error' for d in diagnostics):
                raise AssertionError(diagnostics)

    def test_manifest_covers_every_published_leaf_once_including_disabled(self):
        paths = [item['path'] for item in self.categories]
        self.assertEqual(len(paths), len(set(paths)))
        self.assertEqual(len(paths), len({item['tag'] for item in self.categories}))
        self.assertEqual(set(paths), {str(p.relative_to(ROOT)) for p in (ROOT / 'Rules').rglob('*.list')})
        for item in self.categories:
            self.assertIsInstance(item['default_enabled'], bool)

    def test_exact_destination_owner_is_unique_across_all_published_leaves(self):
        seen = {}
        for item in self.categories:
            for rule in self.rules[item['tag']]:
                key = (rule.kind, rule.value.lower())
                self.assertNotIn(key, seen, f'{key}: {seen.get(key)} and {item["path"]}')
                seen[key] = item['path']

    def test_domain_lists_do_not_inherit_patterns_ua_ip_or_fallback(self):
        for item in self.categories:
            kinds = {r.kind for r in self.rules[item['tag']]}
            if item['path'].startswith('Rules/IP/'):
                self.assertTrue(kinds <= {'ip-cidr', 'ip6-cidr'})
            else:
                self.assertTrue(kinds <= {'host', 'host-suffix'}, item['path'])

    def test_microsoft_core_endpoints_have_explicit_owned_suffix_coverage(self):
        for name in ('office.com', 'office.net', 'outlook.com', 'hotmail.com', 'onenote.com',
                     'windows.com', 'onedrive.com', '1drv.ms', '1drv.com', 'bing.com',
                     'msauth.net', 'msftauth.net', 'skypeassets.com'):
            self.assertTrue(covering_rules(self.rules['Microsoft'], name), name)

    def test_platform_scopes_exclude_unrelated_hosts_and_cloud_tenants(self):
        negative = {
            'Microsoft': ('onedrive.evil.example', 'office.evil.example', 'unrelated.windows.net',
                          'tenant.azureedge.net', 'tenant.azurewebsites.net', 'fabric.io', 'tenor.com',
                          'cdn.unrelated.edgesuite.net', 'foo.uservoice.com'),
            'Apple': ('apple.evil.example', 'iphone.evil.example', 'macbook.evil.example'),
            'Google': ('unrelated-google.example', 'blogspot-unrelated.example', 'tenant.appspot.com'),
        }
        for tag, hosts in negative.items():
            for host in hosts:
                self.assertFalse(covering_rules(self.rules[tag], host), f'{tag}: {host}')

    def test_assembled_domain_model_preserves_named_service_ownership(self):
        config = build_config.sections(build_config.build('standalone'))
        rules, _ = inspect_text('\n'.join(config['[filter_local]']))
        expected = {
            'office.com': 'Microsoft', 'outlook.com': 'Microsoft', 'bing.com': 'Microsoft',
            'onedrive.com': 'Microsoft', 'msauth.net': 'Microsoft',
            'www.google.com': 'Google', 'www.google.co.jp': 'Google',
            'www.apple.com': 'Apple', 'widget.claudemcpcontent.com': 'Claude',
            'hsbc.edge.sdk.awswaf.com': 'direct', 'ws.chatgpt.com': 'OpenAI',
            'cdn.workos.com': 'AI-Dependencies',
        }
        for host, policy in expected.items():
            self.assertEqual(policy, first_hostname_policy(rules, host), host)

    def test_unrelated_provider_tenants_are_left_for_geographic_fallback(self):
        enabled = build_config.load_categories()
        rules = [r for item in enabled for r in self.rules[item['tag']]]
        for host in ('tenant.azureedge.net', 'tenant.azurewebsites.net', 'unrelated.windows.net',
                     'tenant.cloudfront.net', 'tenant.amazonaws.com', 'tenant.appspot.com',
                     'tenant.akadns.net', 'tenant.edgesuite.net', 'tenant.sentry.io'):
            self.assertFalse(covering_rules(rules, host), host)


if __name__ == '__main__':
    unittest.main()
