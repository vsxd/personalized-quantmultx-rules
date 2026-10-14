import importlib.util
import io
from pathlib import Path
import tarfile
import tempfile
import unittest
from unittest.mock import patch

ROOT=Path(__file__).resolve().parents[1]
spec=importlib.util.spec_from_file_location('upstreams',ROOT/'scripts/check_upstreams.py')
u=importlib.util.module_from_spec(spec);spec.loader.exec_module(u)

class UpstreamComparisonTest(unittest.TestCase):
    def test_formatting_is_ignored_but_policy_and_options_are_retained(self):
        a=u.inventory(b'HOST-SUFFIX, Example.COM, DIRECT\n')
        b=u.inventory(b'host-suffix,example.com,direct\n')
        self.assertEqual(a['rules'],b['rules'])
        self.assertNotEqual(a['rules'],u.inventory(b'host-suffix,example.com,proxy\n')['rules'])
        self.assertNotEqual(a['rules'],u.inventory(b'host-suffix,example.com,direct,force-remote-dns\n')['rules'])
    def test_order_changes_and_duplicates_are_visible(self):
        a=b'host,a.example,direct\nhost,b.example,proxy\n'
        b=b'host,b.example,proxy\nhost,a.example,direct\n'
        self.assertEqual(u.inventory(a)['rules'],u.inventory(b)['rules'])
        self.assertNotEqual(u.inventory(a)['ordered_semantic_sha256'],u.inventory(b)['ordered_semantic_sha256'])
        self.assertEqual(u.inventory(a+a)['duplicates']['host,a.example,direct'],2)
    def test_unrecognized_source_format_is_not_silently_discarded(self):
        data=u.inventory(b'DOMAIN-SUFFIX,example.com,PROXY\n')
        self.assertTrue(data['anomalies']);self.assertTrue(data['rules'][0].startswith('UNPARSED:'))
    def test_traversal_and_nonimmutable_refs_fail(self):
        for p in ('../outside','/tmp/out','x/../../out','x\\out'):
            with self.assertRaises(ValueError):u.checked_path(p)
        with self.assertRaises(ValueError):u.checked_commit('master')
    def test_baseline_hash_mismatch_blocks_comparison(self):
        with tempfile.TemporaryDirectory() as d,patch.object(u,'download',return_value=(b'host,example.com,direct\n','https://example.invalid')):
            with self.assertRaisesRegex(ValueError,'SHA256 mismatch'):
                u.compare_file(Path(d),'source','a/b','a'*40,'b'*40,'rules.txt','0'*64)
            self.assertEqual(b'host,example.com,direct\n', (Path(d)/'source/rejected-baseline/rules.txt').read_bytes())

    def test_surge_reference_format_is_not_presented_as_qx(self):
        data = u.inventory(b'DOMAIN-SUFFIX,Example.COM\nIP-CIDR,1.2.3.0/24,no-resolve\n', 'surge')
        self.assertEqual('surge', data['format'])
        self.assertEqual([], data['anomalies'])
        self.assertIn('domain-suffix,example.com', data['rules'])
        self.assertNotIn('host-suffix,example.com', data['rules'])
        self.assertTrue(u.inventory(b'DOMAIN-SUFFIX,example.com\n')['anomalies'])

    def test_domain_list_includes_regex_and_attributes_remain_evidence(self):
        data = u.inventory(b'# comment\nExample.COM @cn\nfull:API.Example.COM\ninclude:category-foo @!cn\nregexp:^Foo#Bar$\n', 'domain-list')
        self.assertEqual([], data['anomalies'])
        self.assertIn('domain:example.com @cn', data['rules'])
        self.assertIn('regexp:^Foo#Bar$', data['rules'])
        self.assertEqual({'include', 'regexp'}, {d['kind'] for d in data['reference_directives']})
        self.assertTrue(u.inventory(b'unknown:Example.COM\n', 'domain-list')['anomalies'])
        self.assertIn('include:CaseSensitiveFile', u.inventory(b'include:CaseSensitiveFile\n', 'domain-list')['rules'])

    def test_new_sources_and_alternative_license_paths_are_configured(self):
        source = {'repository':'https://github.com/example/rules', 'source_branch':'main',
                  'commit':'a' * 40, 'format':'surge', 'license_path':'LICENSE.md',
                  'reference_files':[{'path':'lists/service.list', 'sha256':'f' * 64}]}
        with tempfile.TemporaryDirectory() as d, \
             patch.object(u, 'resolve_branch', return_value='b' * 40), \
             patch.object(u, 'compare_license', return_value={'changed':False}) as license_check, \
             patch.object(u, 'compare_file', return_value={'path':'lists/service.list'}) as file_check:
            result = u.check_source(Path(d), 'new-source', source, 1)
        self.assertEqual([], result['errors'])
        self.assertEqual('LICENSE.md', license_check.call_args.args[-2])
        self.assertEqual(('lists/service.list', 'f' * 64, 'surge'), file_check.call_args.args[-3:])

    def test_missing_license_declaration_is_explicit_not_permission_to_copy(self):
        source = {'repository':'https://github.com/example/rules', 'source_branch':'main',
                  'commit':'a' * 40, 'license_path':None, 'files':[],
                  'comparison_scope':'reference-only', 'reason':'Documentation-only reference, no rule inventory'}
        with tempfile.TemporaryDirectory() as d, patch.object(u, 'resolve_branch', return_value='a' * 40):
            result = u.check_source(Path(d), 'new-source', source, 1)
        self.assertTrue(result['license']['skipped'])
        self.assertIn('do not infer permission', result['license']['reason'])

    def test_tree_inventory_discovers_new_category_paths_without_downloading_content(self):
        def tree(slug, sha, recursive=False):
            entries = {
                ('a' * 40, False): [{'path':'data', 'sha':'c' * 40, 'type':'tree'}],
                ('b' * 40, False): [{'path':'data', 'sha':'d' * 40, 'type':'tree'}],
                ('c' * 40, True): [{'path':'old-service', 'sha':'e' * 40, 'type':'blob'}],
                ('d' * 40, True): [{'path':'new-service', 'sha':'f' * 40, 'type':'blob'}],
            }
            return {'tree':entries[(sha, recursive)]}
        with tempfile.TemporaryDirectory() as d, patch.object(u, 'github_tree', side_effect=tree), \
             patch.object(u, 'download') as download:
            result = u.compare_tree(Path(d), 'source', 'a/b', 'a' * 40, 'b' * 40, ['data'])
        self.assertEqual(['data/new-service'], result['added_paths'])
        self.assertEqual(['data/old-service'], result['removed_paths'])
        self.assertFalse(result['content_reviewed'])
        download.assert_not_called()

    def test_tree_failures_are_incomplete_not_no_changes(self):
        source = {'repository':'https://github.com/example/rules', 'source_branch':'main',
                  'commit':'a' * 40, 'license_path':None, 'files':[], 'inventory_paths':['data']}
        with tempfile.TemporaryDirectory() as d, patch.object(u, 'resolve_branch', return_value='b' * 40), \
             patch.object(u, 'compare_tree', side_effect=ValueError('truncated')):
            result = u.check_source(Path(d), 'new-source', source, 1)
        self.assertIn('TREE INVENTORY: truncated', result['errors'])
        self.assertFalse(result['comparison_complete'])
        self.assertEqual('INCOMPLETE', result['status'])

    def test_nonexistent_inventory_scope_cannot_claim_zero_changes(self):
        with tempfile.TemporaryDirectory() as d, patch.object(u, 'tree_inventory', return_value={}):
            with self.assertRaisesRegex(ValueError, 'no files at either revision'):
                u.compare_tree(Path(d), 's', 'a/b', 'a' * 40, 'b' * 40, ['typo'])

    def test_all_sources_are_read_from_lock_not_a_hardcoded_pair(self):
        import json
        with tempfile.TemporaryDirectory() as d:
            path = Path(d)
            lock = path / 'lock.json'
            lock.write_text(json.dumps({'sources':{'extra':{'repository':'https://github.com/a/b'}}}))
            with patch.object(u, 'check_source', return_value={'files':[], 'errors':[]}) as check:
                status = u.main(['--lock', str(lock), '--output-root', str(path / 'out')])
        self.assertEqual(0, status)
        self.assertEqual('extra', check.call_args.args[1])

    def test_native_domainset_preserves_suffix_versus_exact(self):
        data = u.inventory(b'.Example.COM # suffix source annotation\nExample.COM\n', 'domainset')
        self.assertEqual(['exact:example.com', 'suffix:example.com'], data['rules'])
        self.assertFalse(data['anomalies'])
        self.assertTrue(u.inventory(b'DOMAIN-SUFFIX,example.com\n', 'domainset')['anomalies'])

    def test_empty_source_cannot_claim_a_complete_rule_check(self):
        source = {'repository':'https://github.com/example/rules', 'source_branch':'main',
                  'commit':'a' * 40, 'license_path':None, 'files':[]}
        with tempfile.TemporaryDirectory() as d, patch.object(u, 'resolve_branch', return_value='a' * 40):
            with self.assertRaisesRegex(ValueError, 'no selected files'):
                u.check_source(Path(d), 'empty', source, 1)

    def test_generated_rule_and_license_branches_are_independent(self):
        source = {'repository':'https://github.com/example/rules', 'source_branch':'master',
                  'source_commit':'a' * 40, 'rule_branch':'release', 'rule_commit':'b' * 40,
                  'license_branch':'master', 'license_commit':'a' * 40,
                  'license_sha256':'f' * 64, 'files':[{'path':'rules.txt', 'format':'surge'}]}
        def resolve(slug, branch):
            return {'release':'c' * 40, 'master':'d' * 40}[branch]
        with tempfile.TemporaryDirectory() as d, patch.object(u, 'resolve_branch', side_effect=resolve), \
             patch.object(u, 'compare_license', return_value={}) as license_check, \
             patch.object(u, 'compare_file', return_value={'path':'rules.txt'}) as file_check:
            result = u.check_source(Path(d), 'any-name', source, 1)
        self.assertEqual([], result['errors'])
        self.assertEqual(('b' * 40, 'c' * 40), file_check.call_args.args[3:5])
        self.assertEqual(('a' * 40, 'd' * 40, 'LICENSE', 'f' * 64), license_check.call_args.args[3:])

    def test_license_hash_is_checked_not_just_downloaded(self):
        with tempfile.TemporaryDirectory() as d, patch.object(u, 'download', return_value=(b'license', 'url')):
            with self.assertRaisesRegex(ValueError, 'license SHA256 mismatch'):
                u.compare_license(Path(d), 's', 'a/b', 'a' * 40, 'b' * 40, 'LICENSE', '0' * 64)

    def test_unknown_reference_lines_fail_source_check(self):
        source = {'repository':'https://github.com/example/rules', 'source_branch':'main',
                  'commit':'a' * 40, 'license_path':None, 'files':[{'path':'list'}]}
        delta = {'path':'list', 'baseline_anomalies':[], 'latest_anomalies':[{'text':'unknown'}]}
        with tempfile.TemporaryDirectory() as d, patch.object(u, 'resolve_branch', return_value='a' * 40), \
             patch.object(u, 'compare_file', return_value=delta):
            result = u.check_source(Path(d), 's', source, 1)
        self.assertTrue(result['errors'])
        self.assertTrue(result['comparison_complete'])
        self.assertEqual('REVIEW_REQUIRED', result['status'])

    def test_include_closure_preserves_filters_and_discovers_grandchild(self):
        files = {'data/a':b'include:b @-!cn\n', 'data/b':b'include:c @ads\nfull:B.Example @cn\n',
                 'data/c':b'regexp:^CaseSensitive\\.example$\n'}
        result = u.dependency_inventory(files, ['data/a'], 'data')
        self.assertEqual([], result['errors'])
        self.assertEqual(['data/a','data/b','data/c'], list(result['files']))
        self.assertEqual(['@-!cn'], result['files']['data/a']['reference_directives'][0]['attributes'])
        self.assertFalse(result['expanded_into_rules'])

    def test_missing_include_cycle_and_unknown_syntax_are_incomplete(self):
        files = {'data/a':b'include:b\ninclude:missing\n', 'data/b':b'include:a\nunknown:example.com\n'}
        errors = u.dependency_inventory(files, ['data/a'], 'data')['errors']
        self.assertTrue(any('include cycle' in error for error in errors))
        self.assertTrue(any('missing included file' in error for error in errors))
        self.assertTrue(any('unparsed directive' in error for error in errors))

    def test_indirect_child_change_is_visible_when_root_is_unchanged(self):
        before = {'data/a':b'include:b\n', 'data/b':b'old.example\n'}
        after = {'data/a':b'include:b\n', 'data/b':b'new.example\n'}
        with tempfile.TemporaryDirectory() as d, patch.object(u, 'domain_archive', side_effect=[before,after]):
            result = u.compare_dependencies(Path(d), 's', 'a/b', 'a' * 40, 'b' * 40,
                                             {'directory':'data','roots':['data/a']}, [])
            self.assertTrue((Path(d)/'s/dependencies/diffs/data/b.json').is_file())
        self.assertEqual(['data/b'], result['changed_paths'])
        self.assertEqual([], result['baseline_errors'])

    def test_dependency_archive_does_not_extract_links_or_paths(self):
        payload = io.BytesIO()
        with tarfile.open(fileobj=payload, mode='w:gz') as archive:
            info = tarfile.TarInfo('repo/data/link')
            info.type = tarfile.SYMTYPE
            info.linkname = '/outside'
            archive.addfile(info)
        with patch.object(u, 'urlopen', return_value=io.BytesIO(payload.getvalue())):
            with self.assertRaisesRegex(ValueError, 'unsupported dependency archive entry'):
                u.domain_archive('a/b', 'a' * 40, 'data')

    def test_expanded_lock_covers_all_reference_families_and_formats(self):
        import json
        lock = json.loads((ROOT/'upstream-lock.json').read_text())['sources']
        self.assertTrue({'sve1r','ppmina','blackmatrix7','SukkaW','v2fly','ACL4SSR','Loyalsoldier'}.issubset(lock))
        formats = {item.get('format', source.get('format','qx')) for source in lock.values() for item in source['files']}
        self.assertTrue({'qx','surge','domainset','domain-list'}.issubset(formats))
        for source in lock.values():
            self.assertTrue(source['inventory_paths'])
            self.assertEqual(64, len(source['license_sha256']))
            for item in source['files']:
                self.assertEqual(64, len(item['sha256']))

if __name__=='__main__':unittest.main()
