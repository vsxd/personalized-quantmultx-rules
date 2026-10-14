"""Service boundaries refreshed from official endpoints and scoped MIT inputs."""
from pathlib import Path
import sys
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path[:0] = [str(ROOT / 'scripts'), str(ROOT / 'tests')]
import build_config
from validate_rules import inspect_text
from test_service_coverage import covering_rules, first_hostname_policy


class GlobalReviewTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.leaves = {
            item['tag']: inspect_text((ROOT / item['path']).read_text())[0]
            for item in build_config.load_categories()
        }
        profile = build_config.sections(build_config.build('standalone'))
        cls.assembled = inspect_text('\n'.join(profile['[filter_local]']))[0]

    def test_line_has_main_service_as_well_as_cdn_coverage(self):
        for host in ('access.line.me', 'api.line.me', 'gw.line.naver.jp',
                     'ga2.line-apps.com', 'lin.ee', 'desktop.line-scdn.net'):
            self.assertTrue(covering_rules(self.leaves['Line'], host), host)
            self.assertEqual('Global', first_hostname_policy(self.assembled, host))
        for host in ('unrelated.naver.jp', 'line.me.evil.example', 'linegame.jp'):
            self.assertFalse(covering_rules(self.leaves['Line'], host), host)

    def test_developer_registry_metadata_and_payload_destinations(self):
        for host in ('auth.docker.io', 'registry-1.docker.io', 'dhi.io',
                     'registry.npmjs.org', 'www.npmjs.com', 'pypi.org',
                     'files.pythonhosted.org', 'docs.python.org',
                     'docker-pinata-support.s3.amazonaws.com'):
            self.assertTrue(covering_rules(self.leaves['Tools'], host), host)
            self.assertEqual('Global', first_hostname_policy(self.assembled, host))
        for host in ('unrelated.s3.amazonaws.com', 'unrelated.pythonhosted.org',
                     'tenant.cloudflarestorage.com', 'cdn.auth0.com',
                     'notify.bugsnag.com'):
            self.assertFalse(covering_rules(self.leaves['Tools'], host), host)

    def test_reclassified_products_keep_policy_without_wrong_service_owner(self):
        for host, owner, previous in (
            ('twitteroauth.com', 'Tools', 'X'),
            ('foxcredit.com', 'GlobalDomains', 'Fox'),
            ('foxcredit.org', 'GlobalDomains', 'Fox'),
            ('winticket.jp', 'GlobalDomains', 'AbemaTV'),
            ('www.amebaownd.com', 'Communities', 'AbemaTV'),
            ('static.amebaowndme.com', 'Communities', 'AbemaTV'),
        ):
            self.assertTrue(covering_rules(self.leaves[owner], host), host)
            self.assertFalse(covering_rules(self.leaves[previous], host), host)
            self.assertEqual('Global', first_hostname_policy(self.assembled, host))

    def test_notion_current_site_does_not_claim_shared_content_hosts(self):
        for host in ('www.notion.com', 'www.notion.so', 'www.notion-status.com'):
            self.assertEqual('Global', first_hostname_policy(self.assembled, host), host)
        for host in ('images.ctfassets.net', 'videos.ctfassets.net'):
            self.assertFalse(covering_rules(self.leaves['GlobalDomains'], host), host)


if __name__ == '__main__':
    unittest.main()
