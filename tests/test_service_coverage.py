"""Service routing contracts; offline hostname coverage, not a QX engine.

The allowlist below is an independently recorded vendor snapshot (2026-10-14),
not generated from the rule files. It verifies coverage and scope, without
claiming a device's policy selection, precedence, DNS or reachability.
"""
import importlib.util
import fnmatch
from pathlib import Path
import sys
import unittest


ROOT = Path(__file__).resolve().parents[1]
SERVICES = ROOT / 'Rules' / 'Services'
spec = importlib.util.spec_from_file_location('service_rule_validator', ROOT / 'scripts' / 'validate_rules.py')
validator = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = validator
spec.loader.exec_module(validator)
build_spec = importlib.util.spec_from_file_location('service_config_builder', ROOT / 'scripts' / 'build_config.py')
builder = importlib.util.module_from_spec(build_spec)
build_spec.loader.exec_module(builder)

# https://help.openai.com/en/articles/9247338-network-recommendations-for-chatgpt-errors-on-web-and-apps
# Official main allowlist, as actually read on 2026-10-14. iOS-only troubleshooting
# endpoints and legacy compatibility domains are not added to this fixture.
OPENAI_OFFICIAL_ALLOWLIST = (
    '*.auth.openai.com', '*.chatgpt.com', '*.ct.sendgrid.net',
    '*.intercom.io', '*.intercomcdn.com', '*.oaistatic.com',
    '*.oaiusercontent.com', '*.openai.com', '*.oaistatsig.com',
    'android.chat.openai.com', 'auth0.openai.com', 'cdn.openaimerge.com',
    'cdn.platform.openai.com', 'cdn.workos.com', 'challenges.cloudflare.com',
    'chat.openai.com', 'desktop.chat.openai.com', 'forwarder.workos.com',
    'frontend-apps-multi-region.workos.com', 'humb.apple.com',
    'images.workoscdn.com', 'ios.chat.openai.com', 'js.intercomcdn.com',
    'js.stripe.com', 'o207216.ingest.sentry.io', 'o33249.ingest.sentry.io',
    'rum.browser-intake-datadoghq.com', 'setup.auth.openai.com',
    'setup.workos.com', 'tcr9i.chat.openai.com', 'workos.imgix.net',
)


def covering_rules(rules, hostname):
    """Only domain equality/boundary coverage; deliberately no policy simulation."""
    hostname = hostname.lower()
    return [rule for rule in rules if (
        rule.kind == 'host' and hostname == rule.value.lower()
    ) or (
        rule.kind == 'host-suffix'
        and (hostname == rule.value.lower() or hostname.endswith('.' + rule.value.lower()))
    )]


def first_hostname_policy(rules, hostname):
    """Ordered domain-rule model only; skip IP/GeoIP/UA and QX optimization.

    This detects an earlier broad hostname rule stealing a known service. It
    cannot prove the on-device route when IP rules, user agents, DNS association
    or Quantumult X's optional matching optimization affect the decision.
    """
    hostname = hostname.lower()
    for rule in rules:
        if covering_rules([rule], hostname):
            return rule.policy
        if rule.kind == 'host-keyword' and rule.value.lower() in hostname:
            return rule.policy
        if rule.kind == 'host-wildcard' and fnmatch.fnmatchcase(hostname, rule.value.lower()):
            return rule.policy
        if rule.kind == 'final':
            return rule.policy
    return None


class ServiceCoverageTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.lists = {}
        for name in ('OpenAI', 'OpenAI-Dependencies', 'HSBC', 'Claude'):
            path = SERVICES / f'{name}.list'
            rules, diagnostics = validator.inspect_text(path.read_text(), str(path.relative_to(ROOT)))
            errors = [finding for finding in diagnostics if finding.severity == 'error']
            if errors:
                raise AssertionError(errors)
            cls.lists[name] = rules

    def test_service_lists_have_one_canonical_location(self):
        for name in self.lists:
            with self.subTest(service=name):
                self.assertFalse((ROOT / f'{name}.list').exists(), 'do not restore legacy root copies')
                self.assertTrue((SERVICES / f'{name}.list').is_file())

    def test_service_lists_do_not_gain_keyword_ip_or_final_catchalls(self):
        for name, rules in self.lists.items():
            with self.subTest(service=name):
                self.assertTrue(rules)
                self.assertTrue(all(rule.kind in {'host', 'host-suffix'} for rule in rules))

    def test_hsbc_primary_and_observed_waf_dependency_are_covered(self):
        rules = self.lists['HSBC']
        for hostname in ('www.hsbc.com.hk', 'www.personal.hsbc.com.hk',
                         'rbwm-api.hsbc.com.hk', 'api.payme.hsbc.com.hk'):
            with self.subTest(hostname=hostname):
                self.assertTrue(covering_rules(rules, hostname))
        waf = covering_rules(rules, 'hsbc.edge.sdk.awswaf.com')
        self.assertEqual(1, len(waf))
        self.assertEqual(('host', 'hsbc.edge.sdk.awswaf.com'), (waf[0].kind, waf[0].value))

    def test_hsbc_does_not_capture_other_tenants_or_shared_cdns(self):
        for hostname in (
            'other.edge.sdk.awswaf.com', 'awswaf.com',
            'child.hsbc.edge.sdk.awswaf.com', 'example.cloudfront.net',
            'example.amazonaws.com', 'example.akamai.net', 'tags.tiqcdn.com',
            'hsbc.example.com', 'not-hsbc.com', 'hsbc.com.hk.example.com', 'hsbc-net.com',
        ):
            with self.subTest(hostname=hostname):
                self.assertFalse(covering_rules(self.lists['HSBC'], hostname))

    def test_full_official_openai_allowlist_is_covered_when_dependencies_enabled(self):
        rules = self.lists['OpenAI'] + self.lists['OpenAI-Dependencies']
        self.assertEqual(31, len(OPENAI_OFFICIAL_ALLOWLIST))
        for entry in OPENAI_OFFICIAL_ALLOWLIST:
            hostnames = (entry,) if not entry.startswith('*.') else (
                'probe.' + entry[2:], 'nested.probe.' + entry[2:],
            )
            for hostname in hostnames:
                with self.subTest(official=entry, hostname=hostname):
                    self.assertTrue(covering_rules(rules, hostname))

    def test_openai_core_keeps_dedicated_tenants_and_websockets(self):
        for hostname in (
            'ws.chatgpt.com', 'chatgpt.com', 'auth.openai.com', 'files.oaiusercontent.com',
            'chat.openai.com.cdn.cloudflare.net', 'openaiapi-site.azureedge.net',
            'openaicom.imgix.net', 'production-openaicom-storage.azureedge.net',
            'openaicomproductionae4b.blob.core.windows.net',
            'openaicom-api-bdcpf8c6d2e9atf6.z01.azurefd.net',
            'openai-api.arkoselabs.com', 'o207216.ingest.sentry.io',
            'o33249.ingest.sentry.io', 'chatgpt.livekit.cloud',
        ):
            with self.subTest(hostname=hostname):
                self.assertTrue(covering_rules(self.lists['OpenAI'], hostname))

    def test_shared_openai_dependencies_are_explicitly_outside_the_core(self):
        for hostname in (
            'cdn.workos.com', 'setup.workos.com', 'challenges.cloudflare.com',
            'js.stripe.com', 'humb.apple.com', 'js.intercomcdn.com',
            'example.intercom.io', 'example.ct.sendgrid.net',
            'rum.browser-intake-datadoghq.com',
        ):
            with self.subTest(hostname=hostname):
                self.assertFalse(covering_rules(self.lists['OpenAI'], hostname))
                self.assertTrue(covering_rules(self.lists['OpenAI-Dependencies'], hostname))

    def test_openai_lists_exclude_unrelated_cloud_tenants_and_lookalikes(self):
        rules = self.lists['OpenAI'] + self.lists['OpenAI-Dependencies']
        for hostname in (
            'other.azureedge.net', 'other.z01.azurefd.net', 'other.blob.core.windows.net',
            'other.imgix.net', 'other.arkoselabs.com', 'o123.ingest.sentry.io',
            'api.stripe.com', 'other.workos.com', 'www.cloudflare.com',
            'api.intercom-example.com', 'ct.sendgrid.net.example.com',
            'example.auth0.com', 'other.livekit.cloud', 'register.appattest.apple.com',
            'openai.com.example.com', 'fakeopenai.com', 'notchatgpt.com',
            'openaiusercontent.com', 'files.openaiusercontent.com',
        ):
            with self.subTest(hostname=hostname):
                self.assertFalse(covering_rules(rules, hostname))

    def test_claude_covers_first_party_without_capturing_tool_infrastructure(self):
        for hostname in ('api.anthropic.com', 'platform.claude.com', 'downloads.claude.ai',
                         'mcp-proxy.anthropic.com', 'bridge.claudeusercontent.com',
                         'example.frame.claudeusercontent.com'):
            self.assertTrue(covering_rules(self.lists['Claude'], hostname), hostname)
        for hostname in ('storage.googleapis.com', 'github.com', 'raw.githubusercontent.com',
                         'registry.npmjs.org', 'formulae.brew.sh',
                         'http-intake.logs.us5.datadoghq.com', 'other.b-cdn.net'):
            self.assertFalse(covering_rules(self.lists['Claude'], hostname), hostname)

    def test_assembled_standalone_hostname_order_preserves_service_routes(self):
        config = builder.sections(builder.build(mode='standalone'))
        rules, diagnostics = validator.inspect_text('\n'.join(config['[filter_local]']))
        self.assertFalse([d for d in diagnostics if d.severity == 'error'])
        expected = {
            'www.hsbc.com.hk': 'direct',
            'www.personal.hsbc.com.hk': 'direct',
            'api.payme.hsbc.com.hk': 'direct',
            'hsbc.edge.sdk.awswaf.com': 'direct',
            'ws.chatgpt.com': 'OpenAI',
            'chatgpt.com': 'OpenAI',
            'openaiapi-site.azureedge.net': 'OpenAI',
            'production-openaicom-storage.azureedge.net': 'OpenAI',
            'openaicomproductionae4b.blob.core.windows.net': 'OpenAI',
            'openaicom-api-bdcpf8c6d2e9atf6.z01.azurefd.net': 'OpenAI',
            'api.anthropic.com': 'Claude',
            'platform.claude.com': 'Claude',
            'bridge.claudeusercontent.com': 'Claude',
        }
        # These are the shared entries from the independently captured vendor
        # fixture, not values inferred from the current implementation.
        shared_official = {
            '*.ct.sendgrid.net', '*.intercom.io', '*.intercomcdn.com',
            'cdn.workos.com', 'challenges.cloudflare.com', 'forwarder.workos.com',
            'frontend-apps-multi-region.workos.com', 'humb.apple.com',
            'images.workoscdn.com', 'js.intercomcdn.com', 'js.stripe.com',
            'rum.browser-intake-datadoghq.com', 'setup.workos.com', 'workos.imgix.net',
        }
        for entry in OPENAI_OFFICIAL_ALLOWLIST:
            hostname = 'fixture.' + entry[2:] if entry.startswith('*.') else entry
            expected[hostname] = 'AI-Dependencies' if entry in shared_official else 'OpenAI'
        for hostname, policy in expected.items():
            with self.subTest(hostname=hostname):
                self.assertEqual(policy, first_hostname_policy(rules, hostname))
        # No service keyword or shared AWS/CDN catchall may route these to HSBC
        # or either AI category after the complete general lists are assembled.
        for hostname in ('other.edge.sdk.awswaf.com', 'hsbc.example.test',
                         'not-openai.example.test', 'other.azureedge.net',
                         'example.cloudfront.net', 'other.workos.com'):
            with self.subTest(unrelated=hostname):
                self.assertNotIn(first_hostname_policy(rules, hostname),
                                 {'OpenAI', 'AI-Dependencies', 'Claude', 'HSBC'})

    def test_remote_profile_binds_canonical_service_files_to_effective_policies(self):
        config = builder.sections(builder.build(mode='remote'))
        imports = builder.active(config['[filter_remote]'])
        expected = (
            ('HSBC', 'direct'), ('OpenAI', 'OpenAI'),
            ('Claude', 'Claude'), ('OpenAI-Dependencies', 'AI-Dependencies'),
        )
        for line, (name, policy) in zip(imports[:4], expected):
            with self.subTest(service=name):
                fields = [part.strip() for part in line.split(',')]
                self.assertEqual(builder.BASE + 'master/Rules/Services/' + name + '.list', fields[0])
                self.assertIn('force-policy=' + policy, fields)
                self.assertIn('enabled=true', fields)
        self.assertEqual(4, len(imports[:4]))

    def test_service_policy_defaults_preserve_explicit_direct_and_dependency_inheritance(self):
        config = builder.sections(builder.build(mode='standalone'))
        first_choices = {}
        for line in builder.active(config['[policy]']):
            kind, value = line.split('=', 1)
            fields = [part.strip() for part in value.split(',')]
            if kind.strip() == 'static':
                first_choices[fields[0]] = fields[1]
        self.assertEqual('direct', first_choices['OpenAI'])
        self.assertEqual('direct', first_choices['Claude'])
        self.assertEqual('OpenAI', first_choices['AI-Dependencies'])
        # The config intentionally fixes HSBC via force-policy, so a saved
        # selectable HSBC group cannot silently change the generated route.
        self.assertNotIn('HSBC', first_choices)


if __name__ == '__main__':
    unittest.main()
