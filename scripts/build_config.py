#!/usr/bin/env python3
"""Build remote or self-contained QX profiles. Never fetch, execute or publish secrets."""
from __future__ import annotations
import argparse
import json
import os
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'scripts'))
from validate_rules import inspect_text, validate_policy_references
BASE = 'https://raw.githubusercontent.com/vsxd/personalized-quantmultx-rules/'

def sections(text: str) -> dict[str, list[str]]:
    result: dict[str,list[str]]={}; current=''
    for line in text.splitlines():
        if re.fullmatch(r'\[[a-z_]+\]',line.strip()): current=line.strip();result.setdefault(current,[])
        else: result.setdefault(current,[]).append(line)
    return result

def active(lines: list[str]) -> list[str]:
    return [s.strip() for s in lines if s.strip() and not s.lstrip().startswith(('#',';','//'))]

def build(mode='remote',ref='master',private_text=None):
    if mode not in {'remote', 'standalone'}:
        raise ValueError('mode must be remote or standalone')
    if not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9._/-]*',ref) or '..' in ref.split('/'):
        raise ValueError('ref must be a Git revision, not a URL or arbitrary text')
    config=sections((ROOT/'Config/base.conf').read_text())
    categories=json.loads((ROOT/'Config/categories.json').read_text())
    generated=[]
    for item in categories:
        path=ROOT/item['path']
        if not path.is_file(): raise ValueError(f"Missing owned list: {item['path']}")
        if mode=='remote':
            config['[filter_remote]'].append(f"{BASE}{ref}/{item['path']}, tag={item['tag']}, force-policy={item['policy']}, update-interval=86400, opt-parser=false, enabled=true")
        else:
            generated.append(f"# {item['path']} — effective policy {item['policy']}")
            for line in active(path.read_text().splitlines()):
                fields=[v.strip() for v in line.split(',')]
                if fields[0].lower()=='final': raise ValueError('final forbidden in service lists')
                fields[2]=item['policy']
                generated.append(', '.join(fields))
    private_rules=[]
    if private_text is not None:
        private=sections(private_text)
        for key in ('[server_remote]','[server_local]'):
            config[key]=private.get(key,[]).copy()
        for line in active(private.get('[filter_local]',[])):
            fields=[v.strip() for v in line.split(',')]
            if fields[0].lower() in ('final','geoip','geoip6'): continue
            if line not in active(config['[filter_local]']): private_rules.append(line)
        if private_rules:
            rules, diagnostics = inspect_text('\n'.join(private_rules), 'private filter_local')
            known = {line.split('=', 1)[1].split(',', 1)[0].strip()
                     for line in active(config['[policy]'])}
            for line in active(config['[server_local]']):
                tag = re.search(r'(?:^|,)\s*tag\s*=\s*([^,]+)', line)
                if tag:
                    known.add(tag.group(1).strip())
            diagnostics += validate_policy_references(rules, known)
            errors = [f'{d.file}:{d.line}: {d.message}' for d in diagnostics if d.severity == 'error']
            if errors:
                raise ValueError('Private overrides need review; no output generated:\n' + '\n'.join(errors)
                                 + '\nCustom groups and remote node tags are not inherited implicitly.')
    local=config['[filter_local]']; split=next(i for i,l in enumerate(local) if l.startswith('geoip,'))
    # Personal host overrides first; ordinary local IP rules remain for native QX evaluation.
    config['[filter_local]']=private_rules+generated+local[:split]+local[split:]
    return '\n'.join((key+'\n' if key else '')+'\n'.join(lines).rstrip()+'\n' for key,lines in config.items())

def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--mode',choices=('remote','standalone'),default='remote')
    p.add_argument('--ref',default='master')
    p.add_argument('--private-from',type=Path,help='Import ONLY server sections and non-final local overrides; never CA or scripts')
    p.add_argument('--output',type=Path,required=True)
    a=p.parse_args()
    if a.private_from and a.output.resolve().is_relative_to(ROOT):
        p.error('Private output must stay outside the repository')
    content=build(a.mode,a.ref,a.private_from.read_text() if a.private_from else None)
    a.output.parent.mkdir(parents=True,exist_ok=True)
    # Create private profile with restrictive mode from the first write, including on overwrite.
    fd=os.open(a.output,os.O_WRONLY|os.O_CREAT|os.O_TRUNC,0o600 if a.private_from else 0o644)
    if a.private_from: os.fchmod(fd,0o600)
    with os.fdopen(fd,'w') as handle:handle.write(content)
    print(f'Built {a.mode} profile: {a.output} (private={bool(a.private_from)})')
if __name__=='__main__':main()
