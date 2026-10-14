import importlib.util
from pathlib import Path
import sys
import tempfile
import unittest

SCRIPT = Path(__file__).resolve().parents[1] / 'scripts' / 'validate_rules.py'
spec = importlib.util.spec_from_file_location('validate_rules', SCRIPT)
validator = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = validator
spec.loader.exec_module(validator)


class RuleValidationTest(unittest.TestCase):
    def codes(self, text, severity='error'):
        _, diagnostics = validator.inspect_text(text)
        return {d.code for d in diagnostics if d.severity == severity}

    def test_real_corrupted_bilibili_domain_fails(self):
        self.assertIn('domain', self.codes('host-suffix,Domestic Media.com,China'))
        self.assertEqual(set(), self.codes('host-suffix,bilibili.com,China'))

    def test_host_is_not_a_wildcard_rule(self):
        self.assertIn('domain', self.codes('host,*.example.com,direct'))
        self.assertEqual(set(), self.codes('host-wildcard,*.example.com,direct'))

    def test_noncanonical_and_wrong_family_cidrs_fail(self):
        for text, code in [
            ('ip-cidr,203.74.95.130/28,Global', 'cidr'),
            ('ip-cidr,52.71.40.0/16,Global', 'cidr'),
            ('ip-cidr,2001:db8::/32,direct', 'cidr-family'),
            ('ip6-cidr,192.0.2.0/24,direct', 'cidr-family'),
            ('ip-cidr,0.0.0.0/0,direct', 'cidr-default'),
            ('ip-cidr,192.0.2.1,direct', 'cidr-prefix'),
        ]:
            with self.subTest(text=text):
                self.assertIn(code, self.codes(text))

    def test_foreign_dialect_names_do_not_silently_pass(self):
        for kind in ['url-regex', 'ip-cidr6', 'geoip6', 'filter-lan', 'filter-region', 'via-interface']:
            with self.subTest(kind=kind):
                self.assertIn('rule-type', self.codes(f'{kind},example.com,direct'))

    def test_empty_and_missing_fields_fail(self):
        self.assertIn('empty-list', self.codes('# empty resource\n'))
        for text in ['host,example.com', 'host,,direct', 'host,example.com,', 'host,example.com,direct,']:
            self.assertIn('fields', self.codes(text))

    def test_options_are_validated(self):
        self.assertEqual(set(), self.codes('host,example.com,direct,via-interface=en0'))
        self.assertIn('option', self.codes('host,example.com,direct,typo-option'))
        self.assertIn('option-conflict', self.codes('host,example.com,direct,force-cellular,multi-interface'))

    def test_overbroad_rules_warn_without_rejecting_valid_qx_syntax(self):
        self.assertIn('broad-keyword', self.codes('host-keyword,google,Google', 'warning'))
        self.assertIn('wildcard-tld', self.codes('host-wildcard,apple.*,Apple', 'warning'))
        self.assertIn('shared-domain', self.codes('host-suffix,amazonaws.com,Global', 'warning'))

    def test_duplicates_and_conflicts_are_diagnostic(self):
        text = 'HOST,example.com,direct\nhost,example.com,direct\nhost,example.com,proxy'
        self.assertEqual(set(), self.codes(text))
        self.assertTrue({'duplicate', 'policy-conflict'} <= self.codes(text, 'warning'))

    def test_cross_list_overlap_reported(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            paths = [root / 'a.list', root / 'b.list']
            paths[0].write_text('host,example.com,direct\n')
            paths[1].write_text('host,example.com,proxy\n')
            _, findings = validator.inspect_files(paths, root)
            self.assertIn('cross-list-overlap', {d.code for d in findings})

    def test_dns_option_is_preserved_and_its_behavior_reported(self):
        text = 'host,example.com,Global,force-remote-dns'
        self.assertEqual(set(), self.codes(text))
        self.assertIn('dns-option', self.codes(text, 'warning'))

    def test_force_policy_changes_the_policy_reference_to_validate(self):
        rules, _ = validator.inspect_text('host,example.com,Foreign Media', 'media.list')
        self.assertTrue(validator.validate_policy_references(rules, {'Global'}))
        self.assertEqual([], validator.validate_policy_references(rules, {'Global'}, {'media.list': 'Global'}))
        self.assertTrue(validator.validate_policy_references(rules, {'Global'}, {'media.list': 'Typo'}))

    def test_canonical_examples_and_case(self):
        for text in ['HOST-SUFFIX,Example.com,OpenAI', 'ip6-cidr,2001:db8::/32,direct',
                     'geoip,cn,direct', 'ip-asn,6185,proxy', 'user-agent,Microsoft*,Microsoft']:
            self.assertEqual(set(), self.codes(text), text)


if __name__ == '__main__':
    unittest.main()
