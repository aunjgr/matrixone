#!/usr/bin/env python3
"""Download only the checksum-listed evidence directory at an immutable commit."""
import argparse
import hashlib
import json
from pathlib import Path,PurePosixPath
import re
import urllib.request


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--commit',required=True)
    parser.add_argument('--output',type=Path,required=True)
    args=parser.parse_args()
    if not re.fullmatch('[0-9a-f]{40}',args.commit):raise ValueError('an immutable commit is required')
    args.output.mkdir(mode=0o700)
    prefix='https://raw.githubusercontent.com/aunjgr/matrixone/'+args.commit+'/docs/design/evidence/sirius-cutover-30251/ac6a9ec1ea/'
    with urllib.request.urlopen(prefix+'checksums.json',timeout=90) as response:raw=response.read((1<<20)+1)
    if len(raw)>1<<20:raise ValueError('checksum manifest exceeds bound')
    checksums=json.loads(raw)
    if not isinstance(checksums,dict) or not checksums:raise ValueError('checksum manifest is empty')
    (args.output/'checksums.json').write_bytes(raw)
    for number,(name,expected) in enumerate(checksums.items(),1):
        path=PurePosixPath(name)
        if path.is_absolute() or '..' in path.parts or str(path)!=name or not re.fullmatch('[0-9a-f]{64}',expected):
            raise ValueError('invalid checksum entry')
        target=args.output/name;target.parent.mkdir(mode=0o700,parents=True,exist_ok=True)
        digest=hashlib.sha256();size=0
        with urllib.request.urlopen(prefix+name,timeout=90) as response,target.open('xb') as stream:
            while chunk:=response.read(1<<20):
                size+=len(chunk)
                if size>32<<20:raise ValueError('artifact exceeds chunk bound')
                digest.update(chunk);stream.write(chunk)
        if digest.hexdigest()!=expected:raise ValueError('downloaded artifact checksum differs')
        print(f'{number}/{len(checksums)} verified: {name}',flush=True)


if __name__=='__main__':main()
