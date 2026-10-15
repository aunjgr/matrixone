#!/usr/bin/env python3
"""Replay the published cutover evidence without a GPU or local author files."""
import argparse
import csv
import hashlib
import json
import re
from pathlib import Path, PurePosixPath
import shutil
import subprocess
import sys
import tarfile
import tempfile


def sha(path):
    with path.open('rb') as source:
        return hashlib.file_digest(source,'sha256').hexdigest()


def relative(root, name):
    path=PurePosixPath(name)
    if not isinstance(name,str) or not name or path.is_absolute() or '..' in path.parts or str(path)!=name:
        raise ValueError('invalid archive member path')
    result=root/name
    if result.resolve()!=result or not result.is_relative_to(root):
        raise ValueError('redirected archive member')
    return result


def check_files(root, manifest):
    if not isinstance(manifest,dict) or not manifest:raise ValueError('empty checksum manifest')
    for name,expected in manifest.items():
        path=relative(root,name)
        if not path.is_file() or len(expected)!=64 or sha(path)!=expected:
            raise ValueError('missing or corrupt artifact: '+name)


def join_chunks(root, entry, destination):
    chunks=entry['chunks']
    if not chunks or len(chunks)!=len(set(chunks)):raise ValueError('missing or duplicate profile chunks')
    with destination.open('xb') as output:
        for name in chunks:
            path=relative(root,name)
            if not path.is_file() or not 0<path.stat().st_size<=32<<20:
                raise ValueError('missing or invalid profile chunk')
            with path.open('rb') as source:shutil.copyfileobj(source,output,1<<20)
    if sha(destination)!=entry['sha256']:raise ValueError('reassembled profile checksum differs')


def extract(archive, destination):
    destination.mkdir(mode=0o700)
    total=count=0
    with tarfile.open(archive,'r:gz') as source:
        for member in source:
            count+=1;total+=member.size
            if count>4096 or total>48<<30 or not member.isfile():
                raise ValueError('nonregular or excessive archive members')
            target=relative(destination,member.name)
            target.parent.mkdir(mode=0o700,parents=True,exist_ok=True)
            with target.open('xb') as output, source.extractfile(member) as stream:
                shutil.copyfileobj(stream,output,1<<20)


def records(path):
    return [json.loads(line) for line in path.read_text().splitlines()]


def replay(root, temporary):
    root=root.resolve()
    check_files(root,json.loads((root/'checksums.json').read_text()))
    qualification=json.loads((root/'qualification.json').read_text())
    payload=temporary/'payload'
    extract(root/'cutover-core.tar.gz',payload)
    check_files(payload,json.loads((payload/'checksums.json').read_text()))
    sys.path.insert(0,str(payload/'source/current'))
    import sirius_acceptance as acceptance
    import sirius_campaign_v2 as current
    from sirius_resource import allocation_summary,reconcile_host_pool
    timing=json.loads((payload/'timing/campaign.json').read_text())
    timing_rows=records(payload/'timing/runs.jsonl')
    resource=json.loads((payload/'resource/campaign.json').read_text())
    resource_rows=records(payload/'resource/runs.jsonl')
    allocations=json.loads((payload/'allocations.json').read_text())
    if timing['provenance']['matrixone_revision']!=qualification['head']:
        raise ValueError('qualification head differs from captured head')
    if sha(payload/'provenance/sdk-link.json')!=timing['provenance']['sdk_sha256']:
        raise ValueError('captured SDK manifest differs')
    import sirius_campaign as collector
    if collector.controller_sha256()!=timing['provenance']['controller_sha256']:
        raise ValueError('frozen controller source differs')
    if len(allocations)!=6 or len(qualification['profiles'])!=6:
        raise ValueError('incomplete profile coverage')
    for entry in qualification['profiles']:
        phase=entry['phase']
        if not isinstance(phase,int) or not 1<=phase<=6:raise ValueError('invalid profile phase')
        archive=temporary/f'phase-{phase}.tar.gz'
        join_chunks(root,entry,archive)
        phase_directory=temporary/f'phase-{phase}'
        extract(archive,phase_directory)
        archive.unlink()
        receipt=json.loads((payload/f'profile-receipts/phase-{phase}.json').read_text())
        check_files(phase_directory,{name:value['sha256'] for name,value in receipt['members'].items()})
        if receipt['sha256']!=entry['sha256'] or receipt['archive_complete'] is not True or receipt['export_exit_status']!=0:
            raise ValueError('profile archive receipt differs')
        if receipt['launcher_sha256']!=sha(root/'tools/nsys_archive.py'):
            raise ValueError('profile archive launcher identity differs')
        allocation=json.loads((payload/f'resource/resource-phase-{phase}.json').read_text())
        if allocations[phase-1]!=allocation:raise ValueError('allocation index differs')
        envelope=json.loads((payload/f'resource/query-records-phase-{phase}.json').read_text())
        runs=envelope['excluded_warmups']+envelope['records']+envelope['cleanup_probes']
        raw=allocation_summary(phase_directory/'resource.sqlite',allocation['pid'],runs)
        if any(allocation.get(key)!=value for key,value in raw.items()):
            raise ValueError('allocation summary differs from raw SQLite')
        measured=[span for span in raw['runs'] if span['phase']=='resource-validation']
        cleanup=[span for span in raw['runs'] if span['phase']=='cleanup-probe']
        if len(measured)!=22 or len(cleanup)!=1 or allocation['warmed_baseline_bytes']!=measured[0]['before_bytes'] or allocation['post_cleanup_bytes']!=cleanup[0]['before_bytes']:
            raise ValueError('resource baseline differs from raw trace')
        by_query={row['query_id']:row for row in envelope['records']}
        derived=reconcile_host_pool(allocation,by_query[measured[0]['query_id']],
            by_query[measured[-1]['query_id']],cleanup[0]['query_id'],resource['provenance']['config'])
        if allocation['host_pool_reconciliation']!=derived:
            raise ValueError('host pool reconciliation differs')
        shutil.rmtree(phase_directory)
    lifecycle=json.loads((payload/'lifecycle.json').read_text())
    sanitizer=json.loads((payload/'sanitizer.json').read_text())
    baselines=json.loads((payload/'numeric-baselines.json').read_text())
    for name in qualification['required_command_receipts']:
        receipt=json.loads((payload/'receipts'/(name+'.json')).read_text())
        log=payload/'receipts'/receipt['output_file']
        allowed=(0,99) if name in ('gpu-memcheck','cub-control','native-leakcheck','pinned-control') else (0,)
        if receipt['exit_status'] not in allowed or sha(log)!=receipt['output_sha256']:
            raise ValueError('command receipt or terminal output differs')
    for run in sanitizer['runs']:
        text=(payload/'receipts'/run['id']).read_text()
        errors=re.findall(r'ERROR SUMMARY: (\d+) errors?',text)
        leaks=re.findall(r'LEAK SUMMARY: ([\d,]+) bytes',text)
        if len(errors)!=1 or int(errors[0])!=run['raw_error_count'] or (int(leaks[0].replace(',','')) if leaks else 0)!=run['raw_leak_bytes'] or 'All tests passed (' not in text:
            raise ValueError('raw sanitizer output differs from parsed evidence')
    for case in lifecycle['cases']:
        proof=case['proof']
        if sha(payload/proof['execution_log'])!=proof['execution_log_sha256']:
            raise ValueError('lifecycle execution proof differs')
        scope='mo' if case['id']=='writer-failure' else 'native'
        if sha(payload/'proof-sources'/scope/proof['source_path'])!=proof['source_sha256']:
            raise ValueError('lifecycle barrier source differs')
    csv_rows={role:[] for role in ('native-a','native-b','candidate')}
    for role in csv_rows:
        for round in (1,2,3):
            with (payload/f'receipts/numeric-{role}-{round}.log').open() as source:
                csv_rows[role].extend(csv.DictReader(source))
    for case in baselines['cases']:
        for label,role in (('reference',case['reference']),('candidate','candidate')):
            samples=[float(row['wall_ms'])/1000 for row in csv_rows[role] if row['case']==case['id']]
            if samples!=case[label+'_seconds']:
                raise ValueError('numeric samples differ from raw CSV')
    acceptance_result=acceptance.validate(timing,timing_rows,resource,resource_rows,allocations,
        lifecycle,sanitizer,baselines)
    # The main-side controller is a different recorded revision. Execute its
    # actual summarizer in isolation; never relabel it as the E controller.
    code="import json,sys;from pathlib import Path;sys.path.insert(0,sys.argv[1]);import sirius_campaign_v2 as v;p=Path(sys.argv[2]);print(json.dumps(v.summarize(json.loads((p/'campaign.json').read_text()),[json.loads(x) for x in (p/'runs.jsonl').read_text().splitlines()])))"
    baseline=json.loads(subprocess.check_output([sys.executable,'-B','-c',code,
        str(payload/'source/base'),str(payload/'baseline-timing')],text=True))
    baseline_campaign=json.loads((payload/'baseline-timing/campaign.json').read_text())
    if baseline_campaign['provenance']['matrixone_revision']!=qualification['base']:
        raise ValueError('qualification base differs from baseline capture')
    baseline_rows=records(payload/'baseline-timing/runs.jsonl')
    for key in ('sirius_revision','sdk_sha256','query_sha256','datasets','hardware','config',
                'toolchain','runner_binary_sha256','sdk_build_mode'):
        if baseline_campaign['provenance'][key]!=timing['provenance'][key]:
            raise ValueError('matched timing input differs: '+key)
    if len(baseline_rows)!=744 or len(timing_rows)!=744 or len(resource_rows)!=264:
        raise ValueError('execution coverage differs')
    identifiers=[row['query_id'] for row in baseline_rows+timing_rows+resource_rows]
    if len(identifiers)!=len(set(identifiers)):raise ValueError('query identity reused')
    candidate=current.summarize(timing,timing_rows)
    checks=[]
    for scale in ('SF1','SF10'):
        for metric in ('median_full_suite','sum_query_medians'):
            before=baseline['scales'][scale]['embedded-mo'][metric]
            after=candidate['scales'][scale]['embedded-mo'][metric]
            ratio=after/before
            if ratio>1.05:raise ValueError('matched performance regression')
            checks.append({'scale':scale,'metric':metric,'baseline_seconds':before,
                           'candidate_seconds':after,'ratio':ratio,'limit':1.05})
    return {'head':qualification['head'],'local_acceptance_complete':acceptance_result['local_acceptance_complete'],
            'baseline_timing_runs':len(baseline_rows),'candidate_timing_runs':len(timing_rows),
            'resource_runs':len(resource_rows),'raw_profiles_reconciled':6,
            'unexplained_growth_bytes':[entry['unexplained_growth_bytes'] for entry in allocations],
            'performance':checks,'numeric_gates':acceptance_result['numeric_gates'],
            'remaining_gates':['reviewer-approval']}


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--directory',type=Path,default=Path(__file__).resolve().parent)
    parser.add_argument('--scratch',type=Path)
    args=parser.parse_args()
    with tempfile.TemporaryDirectory(prefix='sirius-cutover-replay-',dir=args.scratch) as temporary:
        result=replay(args.directory,Path(temporary))
    print(json.dumps(result,indent=2,sort_keys=True))


if __name__=='__main__':main()
