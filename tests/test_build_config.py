import importlib.util
from pathlib import Path
import re
import unittest
import json
import tempfile
from unittest.mock import patch

ROOT=Path(__file__).resolve().parents[1]
spec=importlib.util.spec_from_file_location('builder', ROOT/'scripts/build_config.py')
b=importlib.util.module_from_spec(spec);spec.loader.exec_module(b)

class BuildConfigTest(unittest.TestCase):
    def test_policy_graph_has_no_dangling_groups_or_cycles(self):
        config=b.sections(b.build())
        groups={}
        for line in b.active(config['[policy]']):
            _,rest=line.split('=',1);fields=[v.strip() for v in rest.split(',')]
            groups[fields[0]]=[v for v in fields[1:] if '=' not in v]
        builtin={'direct','proxy','reject'}
        def visit(name,stack):
            if name in builtin:return
            self.assertIn(name,groups);self.assertNotIn(name,stack)
            for nxt in groups[name]:visit(nxt,stack+[name])
        for name in groups:visit(name,[])
        for line in b.active(config['[filter_remote]']):
            policy=re.search(r'force-policy=([^,]+)',line).group(1)
            self.assertIn(policy,set(groups)|builtin)
    def test_private_input_only_inherits_authorized_sections(self):
        src='''[server_remote]
https://example.invalid/sub?token=LOCAL-SECRET, enabled=false
[server_local]
vmess=example.invalid:80, password=LOCAL-NODE, tag=Local
[filter_local]
host, internal.example, direct
geoip, cn, proxy
final, proxy
[mitm]
p12=PRIVATE-CA
passphrase=PRIVATE-PASS
[rewrite_remote]
https://example.invalid/remote-code.js, enabled=true
'''
        out=b.build(private_text=src)
        self.assertIn('LOCAL-SECRET',out);self.assertIn('LOCAL-NODE',out)
        self.assertIn('host, internal.example, direct',out)
        for bad in ('PRIVATE-CA','PRIVATE-PASS','remote-code.js','geoip, cn, proxy','final, proxy'):
            self.assertNotIn(bad,out)
    def test_standalone_does_not_depend_on_remote_rule_files(self):
        s=b.sections(b.build('standalone'))
        self.assertEqual(b.active(s['[filter_remote]']),[])
        rules=b.active(s['[filter_local]'])
        self.assertEqual(rules[-1],'final, Final')
        self.assertEqual(sum(l.lower().startswith('final,') for l in rules),1)
        self.assertEqual(rules[-2], 'geoip, cn, direct')
        self.assertEqual(sum(l.lower().startswith('geoip,') for l in rules),1)
        self.assertFalse(any(l.startswith('http') for l in rules))
    def test_private_overrides_reject_old_invalid_syntax_and_unknown_policies(self):
        for line in ('ip-cidr, 168.138.194.151/0, direct',
                     'host, *.example.com, direct',
                     'host, www.hsbc.com.hk, HSBC'):
            with self.assertRaisesRegex(ValueError, 'Private overrides need review'):
                b.build(private_text='[filter_local]\n' + line)
    def test_private_overrides_cannot_silently_restore_broad_capture(self):
        for line in ('host-keyword, ., direct', 'host-wildcard, apple.*, direct',
                     'host-suffix, azureedge.net, direct', 'host-suffix, cn, direct',
                     'host-suffix, co.nz, direct', 'host-suffix, com.ar, direct',
                     'ip-cidr, 17.0.0.0/8, direct', 'user-agent, Microsoft*, direct',
                     'ip-asn, 13335, direct'):
            with self.assertRaisesRegex(ValueError, 'Private overrides need review'):
                b.build(private_text='[filter_local]\n' + line)
    def test_private_base_ranges_are_deduplicated_canonically(self):
        source='[filter_local]\nIP-CIDR,10.0.0.0/8,direct\nip6-cidr,fc00::/7,direct'
        config=b.sections(b.build('standalone',private_text=source))
        self.assertEqual(1, b.active(config['[filter_local]']).count('ip-cidr, 10.0.0.0/8, direct'))
    def test_private_rules_reject_policy_and_option_conflicts_with_each_other(self):
        pairs = [
            'host, internal.example, direct\nhost, internal.example, reject',
            'host, internal.example, direct\nhost, internal.example, direct, force-remote-dns',
            'host-suffix, internal.example, direct\nhost, api.internal.example, Global',
            'ip-cidr, 192.0.2.0/24, direct\nip-cidr, 192.0.2.1/32, proxy',
            'ip6-cidr, 2001:db8::/48, direct\nip6-cidr, 2001:db8::1/128, direct, via-interface=en0',
        ]
        for mode in ('remote', 'standalone'):
            for pair in pairs:
                with self.subTest(mode=mode, pair=pair):
                    with self.assertRaisesRegex(ValueError, 'overlapping policy/options conflict'):
                        b.build(mode, private_text='[filter_local]\n' + pair)
    def test_private_rules_cannot_override_selected_service_or_base_routes(self):
        overrides = [
            'host-suffix, hsbc.com.hk, Global',
            'host, login.microsoftonline.com, Microsoft, force-remote-dns',
            'host, api.openai.com, direct',  # OpenAI group's current direct choice is not policy equality.
            'ip-cidr, 149.154.160.1/32, direct',  # official Telegram transport range
            'ip-cidr, 10.0.0.0/24, proxy',  # base private range
        ]
        for mode in ('remote', 'standalone'):
            for line in overrides:
                with self.subTest(mode=mode, line=line):
                    with self.assertRaisesRegex(ValueError, 'overlapping policy/options conflict'):
                        b.build(mode, private_text='[filter_local]\n' + line)
    def test_private_internal_domains_and_harmless_same_behavior_remain_usable(self):
        source = ('[filter_local]\nhost-suffix, internal.example, direct\n'
                  'host, api.internal.example, direct\nip-cidr, 10.0.0.0/24, direct\n'
                  'host-suffix, HSBC.COM.HK, direct')
        output = b.build('standalone', private_text=source)
        self.assertIn('host, api.internal.example, direct', output)
        self.assertIn('ip-cidr, 10.0.0.0/24, direct', output)
        self.assertNotIn('HSBC.COM.HK', output)
        self.assertEqual(1, output.count('host-suffix, hsbc.com.hk, direct'))
    def test_private_conflicts_use_selected_effective_policies_not_source_labels(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / 'Config').mkdir()
            (root / 'Rules/Services').mkdir(parents=True)
            (root / 'Rules/Services/Test.list').write_text('host-suffix, example.com, IgnoredSourceLabel\n')
            (root / 'Config/categories.json').write_text(json.dumps([
                {'path': 'Rules/Services/Test.list', 'tag': 'Test', 'policy': 'direct'}]))
            (root / 'Config/base.conf').write_text(
                '[policy]\nstatic = Final, proxy\n[filter_remote]\n'
                '[filter_local]\ngeoip, cn, direct\nfinal, Final\n')
            for mode in ('remote', 'standalone'):
                harmless = b.build(mode, root=root, private_text='[filter_local]\nhost, api.example.com, direct')
                self.assertIn('host, api.example.com, direct', harmless)
                source = '[filter_local]\nhost, api.example.com, proxy'
                with self.assertRaisesRegex(ValueError, 'overlapping policy/options conflict'):
                    b.build(mode, root=root, private_text=source)
                # Deliberately disabling the category removes that conflict.
                self.assertIn('host, api.example.com, proxy',
                              b.build(mode, root=root, disable=['Test'], private_text=source))
    def test_explicit_resource_selection_uses_same_manifest_in_both_modes(self):
        items=json.loads((ROOT/'Config/categories.json').read_text())
        disabled=[i for i in items if not i['default_enabled']]
        self.assertTrue(disabled)
        tag=disabled[0]['tag']
        for mode in ('remote','standalone'):
            output=b.build(mode,enable=[tag],disable=['AI-Dependencies'])
            if mode=='remote':
                self.assertIn('tag='+tag+',',output)
                self.assertNotIn('tag=AI-Dependencies,',output)
            else:
                self.assertNotIn('host, cdn.workos.com, AI-Dependencies',output)
        for kwargs in ({'enable':['not-a-category']},{'enable':['OpenAI'],'disable':['OpenAI']}):
            with self.assertRaises(ValueError):b.build(**kwargs)
    def test_manifest_rejects_duplicate_paths_unknown_policy_and_traversal(self):
        valid=json.loads((ROOT/'Config/categories.json').read_text())
        variants=[valid+[valid[0]], [{**valid[0],'policy':'Undefined'}],
                  [{**valid[0],'path':'Rules/../Config/base.conf'}],
                  [{**valid[0],'default_enabled':'false'}]]
        for items in variants:
            with patch.object(b.json,'loads',return_value=items):
                with self.assertRaises(ValueError):b.load_categories()
    def test_private_overrides_may_refer_to_explicit_local_nodes(self):
        source='[server_local]\nvmess=example.invalid:80, password=dummy, tag=MyNode\n[filter_local]\nhost, example.com, MyNode'
        self.assertIn('host, example.com, MyNode',b.build(private_text=source))
    def test_regions_cover_real_chinese_english_flag_forms_and_exclude_placeholders(self):
        s=b.sections(b.build())
        policies={}
        for line in b.active(s['[policy]']):
            if 'server-tag-regex=' in line:
                name=line.split('=',1)[1].split(',',1)[0].strip()
                policies[name]=re.compile(line.split('server-tag-regex=',1)[1].split(',',1)[0])
        samples={'Japan':['日本-优化','🇯🇵 Japan 01'],'United States':['美国LA-优化-GPT','🇺🇸 United States 01'], 'Hong Kong':['香港-优化','🇭🇰 Hong Kong 03'],'Singapore':['新加坡-优化-GPT','🇸🇬 Singapore 03']}
        for region,tags in samples.items():
            for tag in tags:self.assertRegex(tag,policies[region])
            self.assertNotRegex('剩余流量：日本 100GB',policies[region])
    def test_public_generated_config_is_current(self):
        self.assertEqual((ROOT/'Config/quantumult-x.conf').read_text(),b.build())

if __name__=='__main__':unittest.main()
