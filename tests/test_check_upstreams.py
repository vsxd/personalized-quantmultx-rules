import importlib.util
from pathlib import Path
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

if __name__=='__main__':unittest.main()
