"""Official platform endpoint regressions from the 2026-10-14 review.

These independent vendor examples test destination ownership and boundaries.
They do not emulate Quantumult X or prove a device's selected policy/reachability.
"""
import importlib.util
from pathlib import Path
import sys
import unittest


ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location(
    'core_review_validator', ROOT / 'scripts' / 'validate_rules.py')
validator = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = validator
SPEC.loader.exec_module(validator)


def matches(rules, hostname):
    return [rule for rule in rules if (
        rule.kind == 'host' and hostname == rule.value
    ) or (
        rule.kind == 'host-suffix'
        and (hostname == rule.value or hostname.endswith('.' + rule.value))
    )]


class CorePlatformReviewTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.rules = {}
        for platform in ('Apple', 'Microsoft', 'Google'):
            path = ROOT / 'Rules' / 'Platforms' / f'{platform}.list'
            rules, findings = validator.inspect_text(path.read_text(), str(path))
            if any(finding.severity == 'error' for finding in findings):
                raise AssertionError(findings)
            cls.rules[platform] = rules

    def assert_owned(self, platform, hostnames):
        for hostname in hostnames:
            with self.subTest(platform=platform, hostname=hostname):
                owners = matches(self.rules[platform], hostname)
                self.assertTrue(owners)
                self.assertEqual({platform}, {rule.policy for rule in owners})

    def test_apple_current_system_endpoints(self):
        # https://support.apple.com/en-us/101555
        self.assert_owned('Apple', (
            'app-site-association.networking.apple',
            'apple-relay.cloudflare.com', 'apple-relay.fastly-edge.com',
            'icons.axm-usercontent-apple.com', 'upload.appleschoolcontent.com',
            'probe.apple-dns.net', 'nested.probe.apple-dns.net',
        ))

    def test_microsoft_unified_products_and_narrow_auth_endpoints(self):
        # https://learn.microsoft.com/en-us/microsoft-365/enterprise/urls-and-ip-address-ranges
        self.assert_owned('Microsoft', (
            'outlook.cloud.microsoft', 'teams.cloud.microsoft',
            'res.cdn.static.microsoft', 'probe.usercontent.microsoft',
            'account.activedirectory.windowsazure.com',
            'accounts.accesscontrol.windows.net',
            'enterpriseregistration.windows.net', 'graph.windows.net',
            'login.windows.net',
        ))

    def test_google_authentication_and_gemini_named_apis(self):
        # https://accounts.google.com/.well-known/openid-configuration
        # https://ai.google.dev/api/generate-content
        # https://docs.cloud.google.com/gemini/docs/codeassist/set-up-gemini
        self.assert_owned('Google', (
            'oauth2.googleapis.com', 'openidconnect.googleapis.com',
            'ai.google.dev', 'generativelanguage.googleapis.com',
            'cloudaicompanion.googleapis.com', 'cloudcode-pa.googleapis.com',
        ))

    def test_product_additions_do_not_claim_shared_cloud_or_fake_neighbors(self):
        negatives = {
            'Apple': (
                'other.cloudflare.com', 'other.fastly-edge.com',
                'child.apple-relay.cloudflare.com',
                'cp4.cloudflare.com', 'crl3.digicert.com',
                'apple-dns.net.example.org', 'not-apple-dns.net',
            ),
            'Microsoft': (
                'customer.blob.core.windows.net', 'other.windows.net',
                'other.windowsazure.com', 'customer.azurewebsites.net',
                'child.login.windows.net', 'cloud.microsoft.example.org',
                'notcloud.microsoft',
            ),
            'Google': (
                'storage.googleapis.com', 'other.googleapis.com',
                'customer.appspot.com', 'customer.googleusercontent.com',
                'child.oauth2.googleapis.com',
                'generativelanguage.googleapis.com.example.org',
            ),
        }
        for platform, hostnames in negatives.items():
            for hostname in hostnames:
                with self.subTest(platform=platform, hostname=hostname):
                    self.assertFalse(matches(self.rules[platform], hostname))


if __name__ == '__main__':
    unittest.main()
