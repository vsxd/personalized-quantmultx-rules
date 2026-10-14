"""Game/video contracts from the 2026-10-14 source and live-origin review.

These check service coverage and neighboring host boundaries. They do not
simulate Quantumult X DNS, matching optimization or device policy selections.
"""
from pathlib import Path
import unittest

from test_service_coverage import covering_rules, validator


ROOT = Path(__file__).resolve().parents[1]


def service_rules(relative):
    path = ROOT / 'Rules' / relative
    rules, diagnostics = validator.inspect_text(path.read_text(), str(path))
    errors = [finding for finding in diagnostics if finding.severity == 'error']
    if errors:
        raise AssertionError(errors)
    return rules


class GamesVideoReviewTest(unittest.TestCase):
    def test_minecraft_api_and_documented_twitch_extensions_follow_their_service(self):
        # Modern Minecraft API: immutable MIT v2fly data/mojang. Twitch's
        # official /docs/extensions/ documents both the supervisor and the
        # extension-specific content origins under ext-twitch.tv.
        fixtures = {
            'Games/Minecraft.list': ('Game', ('api.minecraftservices.com',)),
            'Media/Video/Twitch.list': ('Global', (
                'supervisor.ext-twitch.tv', 'example-extension.ext-twitch.tv',
            )),
        }
        for relative, (policy, hostnames) in fixtures.items():
            rules = service_rules(relative)
            for hostname in hostnames:
                with self.subTest(file=relative, hostname=hostname):
                    hits = covering_rules(rules, hostname)
                    self.assertTrue(hits)
                    self.assertEqual({policy}, {rule.policy for rule in hits})
                    self.assertFalse(covering_rules(rules, hostname + '.example.com'))

    def test_current_video_image_origins_are_covered(self):
        # Actual public homepage references, observed 2026-10-14. The Bstar
        # picture host is distinct from its already-covered p. asset host.
        fixtures = {
            'Media/Video/AbemaTV.list': ('image.p-c2-x.abema-tv.com',),
            'Media/Video/Bilibili-International.list': (
                'pic.bstarstatic.com', 'p.bstarstatic.com',
            ),
        }
        for relative, hostnames in fixtures.items():
            rules = service_rules(relative)
            for hostname in hostnames:
                with self.subTest(file=relative, hostname=hostname):
                    hits = covering_rules(rules, hostname)
                    self.assertTrue(hits)
                    self.assertEqual({'Global'}, {rule.policy for rule in hits})

    def test_abema_feature_flags_capture_only_the_observed_tenant(self):
        rules = service_rules('Media/Video/AbemaTV.list')
        self.assertTrue(covering_rules(rules, 'api-abematv.bucketeer.jp'))
        for hostname in (
            'bucketeer.jp', 'other.bucketeer.jp',
            'child.api-abematv.bucketeer.jp',
            'api-abematv.bucketeer.jp.example.com',
        ):
            with self.subTest(hostname=hostname):
                self.assertFalse(covering_rules(rules, hostname))

    def test_blog_hosting_and_betting_are_not_classified_as_abema_video(self):
        rules = service_rules('Media/Video/AbemaTV.list')
        for hostname in (
            'ameba.jp', 'amebaownd.com', 'static.amebaowndme.com',
            'dokusho-ojikan.jp', 'winticket.jp',
        ):
            with self.subTest(hostname=hostname):
                self.assertFalse(covering_rules(rules, hostname))


if __name__ == '__main__':
    unittest.main()
