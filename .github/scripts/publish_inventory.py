"""Publish only signed, hash-verified encrypted packages. No private keys are used."""
import base64
import hashlib
import json
import os
import re
import subprocess
import tempfile
import time
import urllib.error
import urllib.request
from pathlib import Path

REPO = 'mrsjj13866-boop/daeyoung-inventory-downloads'
PUBLIC = base64.b64decode('Kppityow07cFPrIRhBHxG3ESUlGSr1lQTeD+F/JGAcU=')
TOKEN = os.environ['GH_TOKEN']
MAX = 200*1024*1024

def version(value):
    if not isinstance(value,str) or not re.fullmatch(r'[0-9]{1,4}\.[0-9]{1,4}\.[0-9]{1,4}',value):
        raise ValueError('Invalid version')
    return tuple(map(int,value.split('.')))

def verify(raw):
    if len(raw)>16384: raise ValueError('Manifest too large')
    envelope=json.loads(raw)
    payload=base64.b64decode(envelope['payload'],validate=True)
    signature=base64.b64decode(envelope['signature'],validate=True)
    with tempfile.TemporaryDirectory() as temp:
        temp=Path(temp)
        (temp/'key.der').write_bytes(bytes.fromhex('302a300506032b6570032100')+PUBLIC)
        (temp/'payload').write_bytes(payload)
        (temp/'signature').write_bytes(signature)
        subprocess.run(['openssl','pkeyutl','-verify','-pubin','-keyform','DER','-inkey',str(temp/'key.der'),'-rawin','-in',str(temp/'payload'),'-sigfile',str(temp/'signature')],check=True,capture_output=True)
    info=json.loads(payload)
    version(info['version'])
    if info['schema']!=1 or type(info['size']) is not int or not 0<info['size']<=MAX:
        raise ValueError('Invalid package size/schema')
    if not re.fullmatch('[a-f0-9]{64}',info['sha256']):raise ValueError('Invalid digest')
    return info

def api(path,data=None,method='GET'):
    headers={'Authorization':'Bearer '+TOKEN,'Accept':'application/vnd.github+json','X-GitHub-Api-Version':'2022-11-28'}
    body=None
    if data is not None:
        body=json.dumps(data).encode()
        headers['Content-Type']='application/json'
    req=urllib.request.Request('https://api.github.com/repos/'+REPO+'/'+path,data=body,headers=headers,method=method)
    with urllib.request.urlopen(req,timeout=60) as response:return json.load(response)

def public_asset(url,expected_size,expected_hash):
    for attempt in range(5):
        try:
            with urllib.request.urlopen(url,timeout=60) as response:
                total=0;digest=hashlib.sha256()
                while True:
                    block=response.read(1024*1024)
                    if not block:break
                    total+=len(block)
                    if total>expected_size:raise ValueError('Oversized uploaded asset')
                    digest.update(block)
            if total!=expected_size or digest.hexdigest()!=expected_hash:
                raise ValueError('Uploaded asset hash mismatch')
            return
        except urllib.error.HTTPError as error:
            if error.code!=404 or attempt==4:raise
            time.sleep(5)

descriptor=json.loads(Path('release-staging/current.json').read_text())
release_version=descriptor['version'];version(release_version)
folder=Path('release-staging')/release_version
raw=(folder/'latest.json').read_bytes();info=verify(raw)
if info['version']!=release_version:raise ValueError('Version mismatch')
count=(info['size']+4194303)//4194304
parts=sorted(folder.glob('part-*.bin'))
if [p.name for p in parts]!=[f'part-{i:03d}.bin' for i in range(count)]:
    raise ValueError('Incomplete package parts')
blob=b''.join(p.read_bytes() for p in parts)
if len(blob)!=info['size'] or hashlib.sha256(blob).hexdigest()!=info['sha256']:
    raise ValueError('Staged package digest mismatch')
tag='v'+release_version
try:release=api('releases/tags/'+tag)
except urllib.error.HTTPError as error:
    if error.code!=404:raise
    release=api('releases',{'tag_name':tag,'target_commitish':'main','name':'대영통운 통합 재고관리 V'+release_version,'body':'서명·암호화된 Windows 자동업데이트 패키지. D 회사 로고 아이콘 적용.','draft':False,'prerelease':False},'POST')
if release['draft'] or release['prerelease']:raise ValueError('Release must be published and stable')
name='inventory-'+release_version+'.bin'
existing=next((a for a in release['assets'] if a['name']==name),None)
if existing is None:
    endpoint='https://uploads.github.com/repos/'+REPO+'/releases/'+str(int(release['id']))+'/assets?name='+name
    req=urllib.request.Request(endpoint,data=blob,method='POST',headers={'Authorization':'Bearer '+TOKEN,'Content-Type':'application/octet-stream','Accept':'application/vnd.github+json'})
    with urllib.request.urlopen(req,timeout=180) as response:json.load(response)
url='https://github.com/'+REPO+'/releases/download/'+tag+'/'+name
public_asset(url,info['size'],info['sha256'])
current=api('contents/latest.json?ref=main')
current_raw=base64.b64decode(current['content'])
previous=verify(current_raw)
if version(previous['version'])>version(release_version):
    print('A newer update is already published; latest.json unchanged.')
elif version(previous['version'])==version(release_version):
    if current_raw!=raw:raise ValueError('Refusing different payload for the same version')
    print('Release already current and verified: '+release_version)
else:
    api('contents/latest.json',{'message':'Publish verified signed V'+release_version+' update','branch':'main','sha':current['sha'],'content':base64.b64encode(raw).decode()},'PUT')
    print('Published and publicly verified update: '+release_version)
