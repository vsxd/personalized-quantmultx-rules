"""Regression contracts from the 2026-10-14 media scope review.

These assertions check domain coverage and category boundaries only, not QX
precedence, selected nodes, DNS geography or end-to-end playback.
"""
from pathlib import Path
import unittest

from test_service_coverage import covering_rules, validator


ROOT = Path(__file__).resolve().parents[1]


def media_rules(relative):
    path = ROOT / 'Rules/Media' / relative
    rules, diagnostics = validator.inspect_text(path.read_text(), str(path))
    errors = [finding for finding in diagnostics if finding.severity == 'error']
    if errors:
        raise AssertionError(errors)
    return rules


class MediaReviewTest(unittest.TestCase):
    def test_official_primary_and_dependency_origins_are_covered(self):
        # MyDisney's page preloads cdn.disneyaccount.com/v5/sdk.js; HBO Max's
        # page uses the API/image origins below. Huxiu exposes its API origins
        # and the Lizhi corporate site links its app and podcast separately.
        fixtures = {
            'Networks/Disney.list': (
                'cdn.disneyaccount.com', 'www.20thcenturystudios.com',
            ),
            'Networks/HBO.list': (
                'www.max.com', 'graphql.prd.api.discomax.com',
                'beam-images.warnermediacdn.com',
            ),
            'News/ChinaNews.list': ('www.huxiu.com', 'api-account.huxiu.com'),
            'Music/ChinaAudio.list': ('www.lizhi.fm', 'www.lzpipi.com'),
        }
        for relative, hosts in fixtures.items():
            rules = media_rules(relative)
            for hostname in hosts:
                with self.subTest(file=relative, hostname=hostname):
                    self.assertTrue(covering_rules(rules, hostname))
                    self.assertFalse(covering_rules(rules, hostname + '.example.com'))

    def test_dedicated_third_party_hosts_do_not_capture_descendants_or_peers(self):
        # These are exact full: entries in v2fly's immutable MIT snapshot
        # c6adacf29cc4fb05e04651fcf03e00989ef9f797, plus HBO's observed image host.
        # A service-specific hostname does not establish wildcard authority.
        fixtures = {
            'Networks/Disney.list': (
                'disney.my.sentry.io', 'disneyplus.com.ssl.sc.omtrdc.net',
                'espn.hb.omtrdc.net', 'espndotcom.tt.omtrdc.net',
            ),
            'Networks/Fox.list': ('foxnewsplayer-a.akamaihd.net',),
            'Networks/HBO.list': ('beam-images.warnermediacdn.com',),
            'Networks/Paramount.list': (
                'cbsi.live.ott.irdeto.com', 'cbsplaylistserver.aws.syncbak.com',
                'cbsservice.aws.syncbak.com',
            ),
            'Networks/Viu.list': (
                'd1k2us671qcoau.cloudfront.net', 'd2anahhhmp1ffz.cloudfront.net',
                'dfp6rglgjqszk.cloudfront.net',
            ),
            'Music/Spotify.list': (
                'audio-ak-spotify-com.akamaized.net',
                'heads4-ak-spotify-com.akamaized.net',
            ),
        }
        for relative, hosts in fixtures.items():
            rules = media_rules(relative)
            for hostname in hosts:
                with self.subTest(file=relative, hostname=hostname):
                    self.assertTrue(covering_rules(rules, hostname))
                    self.assertFalse(covering_rules(rules, 'child.' + hostname))
                    peer = 'unrelated-tenant.' + hostname.split('.', 1)[1]
                    self.assertFalse(covering_rules(rules, peer))

    def test_finance_software_and_sold_publications_have_correct_media_scope(self):
        # foxcredit.org identifies a credit union, lizhi.io a software retailer;
        # Valnet's official Polygon page records its acquisition in 2025.
        for hostname in ('foxcredit.com', 'foxcredit.org'):
            self.assertFalse(covering_rules(media_rules('Networks/Fox.list'), hostname))
        self.assertFalse(covering_rules(media_rules('Music/ChinaAudio.list'), 'lizhi.io'))
        self.assertFalse(covering_rules(media_rules('News/VoxMedia.list'), 'polygon.com'))
        self.assertTrue(covering_rules(media_rules('News/Technology.list'), 'polygon.com'))
        for hostname in ('fxnetwork.com', 'fxnetworks.com'):
            self.assertFalse(covering_rules(media_rules('Networks/Fox.list'), hostname))
            self.assertTrue(covering_rules(media_rules('Networks/Disney.list'), hostname))


if __name__ == '__main__':
    unittest.main()
