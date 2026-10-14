import importlib.util
from pathlib import Path
import re
import unittest

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
        self.assertFalse(any(l.startswith('http') for l in rules))
    def test_private_overrides_reject_old_invalid_syntax_and_unknown_policies(self):
        for line in ('ip-cidr, 168.138.194.151/0, direct',
                     'host, *.example.com, direct',
                     'host, www.hsbc.com.hk, HSBC'):
            with self.assertRaisesRegex(ValueError, 'Private overrides need review'):
                b.build(private_text='[filter_local]\n' + line)
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
