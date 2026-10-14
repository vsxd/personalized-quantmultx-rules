"""Prevent category drift when curated rules are extended or imported."""
import importlib.util
import json
from pathlib import Path
import sys
import unittest

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('category_validator', ROOT / 'scripts' / 'validate_rules.py')
validator = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = validator
spec.loader.exec_module(validator)


class RepositoryCategoriesTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.categories = json.loads((ROOT / 'docs' / 'rule-categories.json').read_text())

    def test_required_categories_have_one_exact_target_owner(self):
        owners = {}
        conflicts = []
        for filename in self.categories['required_order']:
            rules, _ = validator.inspect_text((ROOT / filename).read_text(), filename)
            for rule in rules:
                target = rule.value if rule.kind == 'user-agent' else rule.value.lower()
                key = (rule.kind, target)
                if key in owners:
                    conflicts.append(f'{filename}:{rule.line}: {key} already owned by {owners[key]}')
                else:
                    owners[key] = filename
        self.assertEqual([], conflicts, '\n'.join(conflicts))

    def test_general_policies_are_native_to_our_repository(self):
        for filename, policy in self.categories['policy_by_general_list'].items():
            rules, _ = validator.inspect_text((ROOT / filename).read_text(), filename)
            self.assertEqual({policy}, {r.policy for r in rules}, filename)
            self.assertTrue((ROOT / filename).read_text().startswith('# MAINTENANCE: independently maintained'), filename)

    def test_optional_dependencies_have_a_recorded_fallback(self):
        for allowed in self.categories['conditional_duplicate_keys']:
            for filename in allowed['files']:
                rules, _ = validator.inspect_text((ROOT / filename).read_text(), filename)
                keys = {(r.kind, r.value.lower()) for r in rules}
                self.assertIn((allowed['type'], allowed['target']), keys, filename)

    def test_shared_cloud_is_not_owned_by_microsoft_or_media(self):
        checks = {
            'Rules/Services/Microsoft.list': {'azureedge.net', 'azurewebsites.net'},
            'Rules/Media/ForeignMedia.list': {'sentry.io', 'execute-api.us-east-1.amazonaws.com',
                                            'execute-api.ap-southeast-1.amazonaws.com',
                                            's3-ap-southeast-1.amazonaws.com', 'us-west-2.amazonaws.com'},
        }
        global_rules, _ = validator.inspect_text((ROOT / 'Rules/Region/Global.list').read_text())
        global_targets = {r.value for r in global_rules}
        for filename, targets in checks.items():
            rules, _ = validator.inspect_text((ROOT / filename).read_text())
            self.assertFalse(targets & {r.value for r in rules})
            self.assertTrue(targets <= global_targets)

    def test_domestic_media_does_not_claim_broad_ranges_or_public_dns(self):
        import ipaddress
        rules, _ = validator.inspect_text((ROOT / 'Rules/Media/DomesticMedia.list').read_text())
        for rule in rules:
            if rule.kind == 'ip-cidr':
                self.assertGreaterEqual(ipaddress.ip_network(rule.value).prefixlen, 24)
                self.assertNotEqual('119.29.29.29/32', rule.value)
            if rule.kind == 'ip6-cidr':
                address = ipaddress.ip_network(rule.value).network_address
                if address.ipv4_mapped:
                    self.assertNotIn(address.ipv4_mapped, ipaddress.ip_network('198.18.0.0/15'))

    def test_specific_google_and_game_domains_use_suffix_boundaries(self):
        for filename, domains in {
            'Rules/Services/Google.list': {'appspot.com', 'googlesource.com', 'gmail.com', 'recaptcha.net'},
            'Rules/Games/GamesAll.list': {'epicgames.com'},
        }.items():
            rules, _ = validator.inspect_text((ROOT / filename).read_text())
            self.assertTrue(domains <= {r.value for r in rules if r.kind == 'host-suffix'})


if __name__ == '__main__':
    unittest.main()
