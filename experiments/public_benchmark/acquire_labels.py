"""Fetch AIT-LDSv2 publisher annotations and their exact paired log members."""
import argparse
from concurrent.futures import ThreadPoolExecutor
import hashlib
import json
from pathlib import Path, PurePosixPath
import re
import zipfile
import zlib
import requests

from .range_zip import RangeReader


def acquire_one(item, root):
    scenario = item['key'].removesuffix('.zip')
    if not re.fullmatch('[a-z]+', scenario):
        raise ValueError('invalid publisher scenario name')
    destination = root / scenario
    destination.mkdir(parents=True, exist_ok=True)
    receipt = destination / 'receipt.json'
    if receipt.exists():
        previous = json.loads(receipt.read_text())
        if all(hashlib.sha256((destination / r['name']).read_bytes()).hexdigest() == r['sha256'] for r in previous['members']):
            print(f'{scenario}: verified cached members', flush=True)
            return previous
        raise ValueError('cached member checksum differs')
    url = f'https://zenodo.org/records/5789064/files/{item["key"]}'
    rows = []
    with RangeReader(url, item['size'], max_transfer=512*1024*1024) as reader:
        with zipfile.ZipFile(reader) as archive:
            # Pair exactly the labels with their original log; do not classify
            # an unrelated/unmatched log source as benign.
            names = [x.filename for x in archive.infolist() if not x.is_dir() and re.match(
                r'^labels/intranet_server/logs/(auth\.log|audit/audit\.log|apache2/.*-(access|error)\.log)', x.filename)]
            if not names:
                raise ValueError(f'{scenario}: no supported annotation files')
            targets = sorted(set(names + [n.replace('labels/', 'gather/', 1) for n in names]))
            for name in targets:
                if '..' in PurePosixPath(name).parts or PurePosixPath(name).is_absolute():
                    raise ValueError('unsafe archive member')
                info = archive.getinfo(name)
                if info.file_size > 256*1024*1024 or info.compress_size > 64*1024*1024:
                    raise ValueError(f'{scenario}: member exceeds download/decompression limit: {name}')
                path = destination / name
                if path.exists():
                    content = path.read_bytes()
                    if len(content) != info.file_size or zlib.crc32(content) != info.CRC:
                        raise ValueError('cached member does not match ZIP CRC')
                else:
                    content = archive.read(name)  # zipfile checks member CRC at EOF.
                    path.parent.mkdir(parents=True, exist_ok=True)
                    path.write_bytes(content)
                rows.append({'name':name, 'bytes':info.file_size, 'crc32':f'{info.CRC:08x}',
                             'sha256':hashlib.sha256(content).hexdigest()})
        result = {'scenario':scenario,'url':url,'archive_size':item['size'],
                  'publisher_archive_checksum':item['checksum'],'full_archive_checksum_verified':False,
                  'member_crc_verified':True,'transferred_bytes':reader.transferred,'members':rows}
    receipt.write_text(json.dumps(result,indent=2),encoding='utf-8')
    print(json.dumps({'scenario':scenario,'members':len(rows),'transferred_bytes':result['transferred_bytes']}),flush=True)
    return result


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--output', default='experiments/data/public/ait_ldsv2_selected')
    p.add_argument('--scenario', action='append')
    args = p.parse_args()
    root = Path(args.output).resolve()
    root.mkdir(parents=True,exist_ok=True)
    metadata_path = root / 'zenodo-5789064.json'
    if metadata_path.exists():
        data = json.loads(metadata_path.read_text())
    else:
        response = requests.get('https://zenodo.org/api/records/5789064', timeout=(15,45))
        response.raise_for_status()
        data = response.json()
        metadata_path.write_text(json.dumps(data,indent=2),encoding='utf-8')
    selected = [x for x in data['files'] if not args.scenario or x['key'].removesuffix('.zip') in args.scenario]
    with ThreadPoolExecutor(max_workers=2) as pool:
        list(pool.map(lambda item:acquire_one(item,root),selected))


if __name__ == '__main__':
    main()
