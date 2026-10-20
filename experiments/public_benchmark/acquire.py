"""Download a pinned Zenodo dataset with publisher checksums and bounded sizes."""
import argparse
import hashlib
import json
import os
from pathlib import Path
from urllib.parse import urlparse

import requests


def digest(path, algorithm='sha256'):
    value = hashlib.new(algorithm)
    with Path(path).open('rb') as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b''):
            value.update(chunk)
    return value.hexdigest()


def acquire(record, names, output, max_bytes=256 * 1024 * 1024):
    if not str(record).isdigit():
        raise ValueError('numeric Zenodo record required')
    root = Path(output).resolve()
    root.mkdir(parents=True, exist_ok=True)
    metadata_path = root / f'zenodo-{record}.json'
    if metadata_path.exists():
        metadata = json.loads(metadata_path.read_text(encoding='utf-8'))
    else:
        response = requests.get(f'https://zenodo.org/api/records/{record}', timeout=(15, 45))
        response.raise_for_status()  # No access-control bypass or retry loop.
        metadata = response.json()
        metadata_path.write_text(json.dumps(metadata, indent=2), encoding='utf-8')
    files = {item['key']: item for item in metadata['files']}
    receipt = []
    for name in names:
        if Path(name).name != name or '/' in name or '\\' in name:
            raise ValueError('only an explicit flat filename is allowed')
        item = files[name]
        if item['size'] > max_bytes:
            raise ValueError(f'{name}: {item["size"]} bytes exceeds approved download bound')
        algorithm, expected = item['checksum'].split(':', 1)
        if algorithm not in ('md5', 'sha256'):
            raise ValueError('unsupported publisher checksum')
        path = root / name
        if path.exists():
            if path.stat().st_size != item['size'] or digest(path, algorithm) != expected:
                raise ValueError(f'existing {name} does not match publisher checksum; left untouched')
        else:
            url = f'https://zenodo.org/records/{record}/files/{name}'
            temporary = path.with_suffix(path.suffix + '.partial')
            if temporary.exists():
                raise ValueError(f'incomplete download exists: {temporary}; inspect before retry')
            with requests.get(url, stream=True, timeout=(15, 60)) as response:
                response.raise_for_status()
                if urlparse(response.url).hostname != 'zenodo.org':
                    raise ValueError('unexpected download redirect')
                count = 0
                with temporary.open('xb') as stream:
                    for chunk in response.iter_content(1024 * 1024):
                        count += len(chunk)
                        if count > item['size'] or count > max_bytes:
                            raise ValueError('download exceeded declared size')
                        stream.write(chunk)
                if count != item['size'] or digest(temporary, algorithm) != expected:
                    raise ValueError('publisher checksum/size mismatch; partial file retained')
                os.replace(temporary, path)
        receipt.append({'file': name, 'bytes': item['size'], 'publisher_checksum': item['checksum'],
                        'sha256': digest(path), 'record': str(record)})
        print(json.dumps(receipt[-1]), flush=True)
    (root / 'download_receipt.json').write_text(json.dumps(receipt, indent=2), encoding='utf-8')
    return receipt


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--record', default='8263181')
    parser.add_argument('--file', action='append', dest='files')
    parser.add_argument('--output', default='experiments/data/public/ait_ads')
    args = parser.parse_args()
    acquire(args.record, args.files or ['ait_ads.zip', 'labels.csv'], args.output)
