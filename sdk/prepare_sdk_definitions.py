#!/usr/bin/env python3
"""Deterministic, published ODbL derivative. Never turns tracker data into malware rules."""
import argparse, hashlib, json, pathlib, re
parser=argparse.ArgumentParser()
parser.add_argument('--source',type=pathlib.Path,default=pathlib.Path('definitions/source/exodus-trackers.json'))
parser.add_argument('--output',type=pathlib.Path,default=pathlib.Path('app/src/main/assets/definitions/exodus-sdk.json'))
args=parser.parse_args()
raw=args.source.read_bytes(); rows=json.loads(raw)['trackers']; accepted=[]; excluded=[]
for row in rows:
    if not row.get('is_in_exodus') or 'Advertisement' not in row.get('category',[]): continue
    prefixes=[]; domains=[]; unsupported=[]
    for part in row.get('code_signature','').split('|'):
        value=part.replace('\\\\.','.').replace('\\.','.').strip().strip('^$').rstrip('./').replace('/','.')
        if value and re.fullmatch(r'[A-Za-z_$][A-Za-z0-9_$]*(\.[A-Za-z_$][A-Za-z0-9_$]*)+',value): prefixes.append(value)
        elif part: unsupported.append(part)
    for part in row.get('network_signature','').split('|'):
        value=part.replace('\\\\.','.').replace('\\.','.').strip().strip('^$').lower()
        if re.fullmatch(r'[a-z0-9](?:[a-z0-9-]*[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]*[a-z0-9])?)+',value): domains.append(value)
        elif part: unsupported.append(part)
    if not prefixes and not domains: excluded.append({'id':row['id'],'name':row['name'],'reason':'No supported literal signatures'});continue
    accepted.append({'id':row['id'],'name':row['name'],'categories':sorted(row['category']),'codePackagePrefixes':sorted(set(prefixes)),
        'networkDomains':sorted(set(domains)),'sourceUrl':'https://etip.exodus-privacy.eu.org/trackers/'+row['id'],'unsupportedSignatures':unsupported})
# Local narrowing (recorded in the output). Upstream prefixes that cover a whole vendor namespace or
# non-advertising components mislabel unrelated apps: "com.bytedance" tags TikTok/CapCut as Pangle.
# Pangle's ad SDK classes live under com.bytedance.sdk.openadsdk (e.g. TTAdSdk).
NARROWED={'Pangle':{'remove':['com.bytedance'],'add':['com.bytedance.sdk.openadsdk'],
    'reason':'Vendor-wide prefix matched non-advertising ByteDance apps; narrowed to the Pangle ad SDK package.'},
  'Huawei Mobile Services (HMS) Core':{'remove':['com.huawei.agconnect','com.huawei.hms.analytics','com.huawei.hms.flutter.analytics',
    'com.huawei.hms.location','com.huawei.hms.plugin.analytics','com.huawei.hms.support.api.push','com.huawei.updatesdk'],'add':[],
    'reason':'Location, push, analytics and update components are not advertising; only the ads plugin prefix is kept.'}}
adjustments=[]
for rule in accepted:
    change=NARROWED.get(rule['name'])
    if not change: continue
    missing=[p for p in change['remove'] if p not in rule['codePackagePrefixes']]
    assert not missing, ('Upstream changed; review narrowing', rule['name'], missing)
    rule['codePackagePrefixes']=sorted((set(rule['codePackagePrefixes'])-set(change['remove']))|set(change['add']))
    assert rule['codePackagePrefixes'] or rule['networkDomains'], rule['name']
    adjustments.append({'id':rule['id'],'name':rule['name'],'removedPrefixes':change['remove'],'addedPrefixes':change['add'],'reason':change['reason']})
assert len(adjustments)==len(NARROWED), 'Narrowing target missing upstream'
payload={'schemaVersion':1,'snapshotDate':'2026-10-02','sourceUrl':'https://etip.exodus-privacy.eu.org/trackers/export',
 'sourceSha256':hashlib.sha256(raw).hexdigest(),'databaseLicense':'ODbL-1.0','contentsLicense':'DbCL-1.0','databaseLicenseUrl':'https://opendatacommons.org/licenses/odbl/1-0/','contentsLicenseUrl':'https://opendatacommons.org/licenses/dbcl/1-0/',
 'attribution':'Exodus Privacy / ETIP tracker database; adapted literal advertising-framework signatures.',
 'interpretation':'Embedded advertising library or packaged reference; not an adware or popup-ownership verdict.',
 'sourceRecordCount':len(rows),'rules':sorted(accepted,key=lambda x:x['id']),'excluded':excluded,'localAdjustments':adjustments}
args.output.parent.mkdir(parents=True,exist_ok=True)
args.output.write_text(json.dumps(payload,ensure_ascii=False,indent=2)+'\n')
print(json.dumps({'sdk_rules':len(accepted),'excluded':len(excluded),'sha256':hashlib.sha256(args.output.read_bytes()).hexdigest()}))
