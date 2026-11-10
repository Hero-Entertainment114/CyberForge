#!/usr/bin/env python3
"""Draft missing CyberForge UI translations with an already-running local Ollama model.

No cloud endpoint is used. This tool is opt-in, read-only by default, and writes only
when --apply is supplied. Review generated language packs before shipping them.
"""
from __future__ import annotations
import argparse
import json
import re
import sys
import urllib.error
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
LOCALES = ('en','vi','es','fr','de','pt','ja','ko','zh','ru','ar','hi')
LANG_NAMES = {
 'en':'English','vi':'Vietnamese','es':'Spanish','fr':'French','de':'German','pt':'Brazilian Portuguese',
 'ja':'Japanese','ko':'Korean','zh':'Simplified Chinese','ru':'Russian','ar':'Arabic','hi':'Hindi'
}
PLACEHOLDER_RE = re.compile(r'\{[^{}]+\}|\$\{[^{}]+\}|%\([^)]+\)[a-zA-Z]|%[sdif]')

def contains_code_only(text: str) -> bool:
    t=text.strip()
    return (not t or t.startswith(('http://','https://','file://')) or
            bool(re.fullmatch(r'[A-Z0-9_./:-]+',t)) or
            t.startswith(('`','<code')))

def ollama_chat(endpoint: str, model: str, language: str, batch: list[tuple[str,str]]) -> dict[str,str]:
    rows=[{'id':i,'source':source} for i,(_,source) in enumerate(batch)]
    prompt=(
      f'Translate each UI string into {LANG_NAMES[language]}. Return ONLY valid JSON as '
      '{"translations":[{"id":0,"translation":"..."}]}. Preserve every placeholder, '
      'number, keyboard shortcut, product name, protocol name, file extension, command, '
      'API path and identifier exactly. Translate natural-language UI text and error messages. '
      'Do not add explanations or markdown. Keep each translation concise and natural.\n'
      + json.dumps(rows,ensure_ascii=False)
    )
    payload={'model':model,'messages':[{'role':'user','content':prompt}],'stream':False,'format':'json','options':{'temperature':0}}
    request=urllib.request.Request(endpoint.rstrip('/')+'/api/chat',data=json.dumps(payload).encode('utf-8'),headers={'Content-Type':'application/json'})
    with urllib.request.urlopen(request,timeout=180) as response:
        data=json.loads(response.read().decode('utf-8'))
    content=data.get('message',{}).get('content','')
    parsed=json.loads(content)
    result={}
    for item in parsed.get('translations',[]):
        idx=int(item['id']); translation=str(item['translation']).strip()
        if 0<=idx<len(batch) and translation:
            source=batch[idx][1]
            if sorted(PLACEHOLDER_RE.findall(source)) != sorted(PLACEHOLDER_RE.findall(translation)):
                continue
            result[batch[idx][0]]=translation
    return result

def main() -> int:
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--model',required=True,help='Model already installed in local Ollama, for example qwen2.5:1.5b')
    parser.add_argument('--endpoint',default='http://127.0.0.1:11434',help='Local Ollama endpoint; must resolve to loopback')
    parser.add_argument('--languages',default='vi,es,fr,de,pt,ja,ko,zh,ru,ar,hi')
    parser.add_argument('--batch-size',type=int,default=8)
    parser.add_argument('--max-chars',type=int,default=4500)
    parser.add_argument('--apply',action='store_true',help='Write reviewed/drafted values into locale JSON files. Without this flag, only report counts.')
    args=parser.parse_args()
    if not 1<=args.batch_size<=20 or not 500<=args.max_chars<=8000:
        parser.error('batch-size must be 1-20 and max-chars must be 500-8000')
    from urllib.parse import urlsplit
    parsed=urlsplit(args.endpoint)
    if parsed.scheme!='http' or parsed.hostname not in {'127.0.0.1','localhost','::1'}:
        parser.error('Only a local HTTP Ollama endpoint is allowed; cloud endpoints are rejected.')
    en=json.loads((ROOT/'locales'/'en.json').read_text(encoding='utf-8'))['messages']
    requested=[x.strip().lower() for x in args.languages.split(',') if x.strip()]
    if any(x not in LOCALES for x in requested):
        parser.error('Choose supported locale codes: '+','.join(LOCALES))
    for lang in requested:
        path=ROOT/'locales'/f'{lang}.json'; catalog=json.loads(path.read_text(encoding='utf-8')); messages=catalog['messages']
        pending=[]
        for key in sorted(messages):
            current=messages[key]
            english=en.get(key,key)
            # A message is a candidate when it is still the source key or English fallback.
            if current not in {key,english}: continue
            source=english if english!=key else key
            if lang=='vi' and source==key and re.search(r'[ăâđêôơưáàảãạắằẳẵặ]',source.lower()):
                continue
            if contains_code_only(source): continue
            pending.append((key,source))
        translated={}
        batches=[]; current=[]; size=0
        for item in pending:
            cost=len(item[1])+24
            if current and (len(current)>=args.batch_size or size+cost>args.max_chars):
                batches.append(current); current=[]; size=0
            current.append(item); size+=cost
        if current:batches.append(current)
        for index,batch in enumerate(batches,1):
            try:
                result=ollama_chat(args.endpoint,args.model,lang,batch)
                translated.update(result)
                print(f'{lang}: batch {index}/{len(batches)} translated {len(result)}/{len(batch)}',flush=True)
            except (urllib.error.URLError,TimeoutError,ValueError,KeyError,TypeError) as exc:
                print(f'{lang}: batch {index} failed: {type(exc).__name__}: {exc}',file=sys.stderr,flush=True)
        if args.apply:
            messages.update(translated)
            path.write_text(json.dumps(catalog,ensure_ascii=False,indent=2)+'\n',encoding='utf-8')
        print(f'{lang}: candidate={len(pending)} drafted={len(translated)} applied={bool(args.apply)}')
    print('Review generated translations for security meaning, terminology and placeholders before release.')
    return 0

if __name__=='__main__':
    raise SystemExit(main())
