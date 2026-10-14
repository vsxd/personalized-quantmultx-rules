"""Common downloads preserve curated leaves and explicit selection boundaries."""
from collections import Counter
import json
from pathlib import Path
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'scripts'))
import build_config as builder
from build_bundles import generate_bundles, write_bundles


class BundleFixtureTest(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        (self.root / 'Config').mkdir()
        (self.root / 'Config/base.conf').write_text(
            '[policy]\nstatic = Global, proxy\nstatic = China, direct\n'
            'static = Final, proxy\n[server_remote]\n[server_local]\n'
            '[filter_remote]\n[filter_local]\ngeoip, cn, direct\nfinal, Final\n')
        self.items = [
            {'path': 'Rules/Core/Service.list', 'tag': 'Service', 'policy': 'direct'},
            {'path': 'Rules/Common/First.list', 'tag': 'First', 'policy': 'Global', 'remote_group': 'Global'},
            {'path': 'Rules/Common/China.list', 'tag': 'ChinaLeaf', 'policy': 'China', 'remote_group': 'China'},
            {'path': 'Rules/Common/Second.list', 'tag': 'Second', 'policy': 'Global', 'remote_group': 'Global'},
            {'path': 'Rules/Optional/Extra.list', 'tag': 'Extra', 'policy': 'reject', 'default_enabled': False},
            {'path': 'Rules/IP/Transport.list', 'tag': 'Transport', 'policy': 'Global'},
        ]
        bodies = [
            'host, core.example.com, direct\n',
            '# MIT first source license\nHOST, first.example.com, UnusedSourceLabel, force-remote-dns\n'
            'host, repeated.example.com, Global\n',
            '# second source license\nhost-suffix, china.example.com, China\n',
            '# Third source notice\nhost, second.example.com, Global\n'
            'host, repeated.example.com, Global\n',
            'host, optional.example.com, reject\n',
            'ip-cidr, 192.0.2.1/32, Global\n',
        ]
        for item, body in zip(self.items, bodies):
            path = self.root / item['path']
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(body)
        self.save_manifest()

    def save_manifest(self):
        (self.root / 'Config/categories.json').write_text(json.dumps(self.items))

    def resources(self, **options):
        return builder.remote_resources(builder.load_categories(root=self.root, **options), self.root)

    def test_complete_groups_replace_members_at_first_position(self):
        resources = self.resources()
        self.assertEqual(['Service', 'Common-Global', 'Common-China', 'Transport'],
                         [item['tag'] for item in resources])
        self.assertEqual(['Rules/Common/First.list', 'Rules/Common/Second.list'],
                         resources[1]['source_paths'])
        self.assertEqual('Bundles/Global.list', resources[1]['path'])
        self.assertEqual('Global', resources[1]['policy'])

    def test_disabled_group_member_uses_only_remaining_individual_leaves(self):
        resources = self.resources(disable=['First'])
        self.assertEqual(['Service', 'Common-China', 'Second', 'Transport'],
                         [item['tag'] for item in resources])
        self.assertNotIn('Bundles/Global.list', [item['path'] for item in resources])
        self.assertNotIn('Rules/Common/First.list', [path for item in resources for path in item['source_paths']])
        output = builder.build(root=self.root, disable=['First'])
        self.assertIn('Rules/Common/Second.list, tag=Second,', output)
        self.assertNotIn('Bundles/Global.list', output)

    def test_optional_toggle_and_independent_disable_preserve_full_common_groups(self):
        resources = self.resources(enable=['Extra'], disable=['Service'])
        self.assertEqual(['Common-Global', 'Common-China', 'Extra', 'Transport'],
                         [item['tag'] for item in resources])
        self.assertEqual(['Rules/Optional/Extra.list'], resources[2]['source_paths'])
        self.assertNotIn('Common-China', [item['tag'] for item in self.resources(disable=['ChinaLeaf'])])

    def test_generated_text_is_deterministic_and_preserves_notices_options_and_multiplicity(self):
        generated = generate_bundles(self.root)
        self.assertEqual(generated, generate_bundles(self.root))
        global_text = generated['Bundles/Global.list']
        self.assertIn('# MIT first source license', global_text)
        self.assertIn('# Third source notice', global_text)
        self.assertIn('# Source leaf: Rules/Common/First.list', global_text)
        self.assertIn('# Source leaf: Rules/Common/Second.list', global_text)
        self.assertIn('host, first.example.com, Global, force-remote-dns', global_text)
        self.assertNotIn('UnusedSourceLabel', global_text)
        self.assertEqual(2, global_text.count('host, repeated.example.com, Global'))
        by_path = {item['path']: item for item in builder.load_categories(root=self.root)}
        for resource in self.resources():
            if resource['path'] not in generated:
                continue
            actual, diagnostics = builder.inspect_text(generated[resource['path']])
            self.assertFalse([d for d in diagnostics if d.severity == 'error'])
            expected = [rule for path in resource['source_paths']
                        for rule in builder.category_rules(by_path[path], self.root)]
            self.assertEqual(Counter(map(builder.semantic_key, expected)),
                             Counter(map(builder.semantic_key, actual)))
            self.assertEqual(list(map(builder.semantic_key, expected)),
                             list(map(builder.semantic_key, actual)))

    def test_profile_builds_do_not_write_bundles(self):
        builder.build(root=self.root)
        builder.build('standalone', root=self.root)
        builder.build(root=self.root, private_text='[server_local]\n')
        self.assertFalse((self.root / 'Bundles').exists())
        written = write_bundles(self.root)
        self.assertEqual(generate_bundles(self.root), written)
        self.assertTrue(all((self.root / path).read_text() == text for path, text in written.items()))

    def test_manifest_blocks_unsafe_mixed_or_nondefault_groups(self):
        originals = json.loads(json.dumps(self.items))
        variants = [(1, {'remote_group': '../escape'}), (1, {'remote_group': None}),
                    (3, {'policy': 'China'}), (1, {'default_enabled': False}),
                    (4, {'remote_group': 'Global', 'default_enabled': True, 'policy': 'Global'}),
                    (5, {'remote_group': 'Global'}), (0, {'tag': 'Common-Global'})]
        for index, updates in variants:
            with self.subTest(updates=updates):
                self.items = json.loads(json.dumps(originals))
                self.items[index].update(updates)
                self.save_manifest()
                with self.assertRaises(ValueError):
                    builder.load_categories(root=self.root)

    def test_without_declared_groups_no_bundle_is_invented(self):
        for item in self.items:
            item.pop('remote_group', None)
        self.save_manifest()
        self.assertEqual({}, generate_bundles(self.root))
        self.assertEqual(5, len(self.resources()))


class RepositoryBundleTest(unittest.TestCase):
    def test_default_profile_has_eleven_downloads_and_keeps_dedicated_services(self):
        resources = builder.remote_resources(builder.load_categories())
        self.assertEqual(11, len(resources))
        self.assertEqual({'HSBC', 'OpenAI', 'Claude', 'OpenAI-SharedDependencies',
                          'Apple', 'Microsoft', 'Google', 'TelegramIP',
                          'Common-China', 'Common-Global', 'Common-Game'},
                         {item['tag'] for item in resources})
        self.assertEqual(12, len(builder.remote_resources(builder.load_categories(enable=['BilibiliPCDNReject']))))

    def test_committed_bundles_match_source_and_complete_default_coverage(self):
        expected = generate_bundles()
        self.assertEqual(set(expected), {str(path.relative_to(ROOT)) for path in (ROOT / 'Bundles').glob('*.list')})
        for path, text in expected.items():
            self.assertEqual(text, (ROOT / path).read_text(), path)
        source_rules = [rule for item in builder.load_categories()
                        for rule in builder.category_rules(item)]
        downloaded_rules = []
        for resource in builder.remote_resources(builder.load_categories()):
            rules, diagnostics = builder.inspect_text((ROOT / resource['path']).read_text())
            self.assertFalse([d for d in diagnostics if d.severity == 'error'])
            downloaded_rules.extend(builder.Rule(r.file, r.line, r.kind, r.value,
                                                resource['policy'], r.options) for r in rules)
        self.assertEqual(Counter(map(builder.semantic_key, source_rules)),
                         Counter(map(builder.semantic_key, downloaded_rules)))


if __name__ == '__main__':
    unittest.main()
