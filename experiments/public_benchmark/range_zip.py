"""Bounded ZIP member reads using ordinary public HTTP byte ranges (no full archive)."""
import argparse
import io
import json
from collections import OrderedDict
from pathlib import Path
import re
from urllib.parse import urlparse
import zipfile

import requests


class RangeReader(io.RawIOBase):
    def __init__(self, url, size, max_transfer=512 * 1024 * 1024):
        if urlparse(url).hostname != 'zenodo.org':
            raise ValueError('only the pinned public Zenodo host is allowed')
        self.url, self.size, self.position = url, int(size), 0
        self.max_transfer, self.transferred = int(max_transfer), 0
        self.session = requests.Session()
        self.cache = OrderedDict()

    def readable(self):
        return True

    def seekable(self):
        return True

    def tell(self):
        return self.position

    def seek(self, offset, whence=0):
        pos = offset if whence == 0 else (self.position if whence == 1 else self.size) + offset
        if pos < 0 or pos > self.size:
            raise ValueError('seek outside archive')
        self.position = pos
        return pos

    def read(self, size=-1):
        count = self.size - self.position if size < 0 else min(size, self.size - self.position)
        if not count:
            return b''
        start, stop = self.position, self.position + count - 1
        for (left, right), cached in self.cache.items():
            if left <= start and stop <= right:
                self.position += count
                return cached[start-left:stop-left+1]
        block = 256 * 1024
        left = start // block * block
        right = min(self.size-1, ((stop // block)+1)*block-1)
        transfer_count = right-left+1
        if self.transferred + transfer_count > self.max_transfer:
            raise ValueError('bounded range-read transfer budget exhausted')
        with self.session.get(self.url, headers={'Range':f'bytes={left}-{right}', 'Accept-Encoding':'identity'},
                              stream=True, timeout=(15, 60)) as response:
            response.raise_for_status()
            expected = f'bytes {left}-{right}/{self.size}'
            if response.status_code != 206 or response.headers.get('Content-Range') != expected:
                raise ValueError('server did not honor byte range; refusing full download')
            body = response.raw.read(transfer_count + 1)
            if len(body) != transfer_count:
                raise ValueError('truncated range response')
        self.transferred += transfer_count
        if transfer_count <= 4 * 1024 * 1024:
            self.cache[(left, right)] = body
            if len(self.cache) > 12:
                self.cache.popitem(last=False)
        self.position += count
        return body[start-left:stop-left+1]

    def close(self):
        if hasattr(self, 'session'):
            self.session.close()
        super().close()


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--scenario', default='russellmitchell')
    parser.add_argument('--size', type=int, default=7132670599)
    parser.add_argument('--match', default='labels/|dataset.yml$|attacks.log$')
    args = parser.parse_args()
    if not re.fullmatch('[a-z]+', args.scenario):
        raise ValueError('invalid scenario name')
    with RangeReader(f'https://zenodo.org/records/5789064/files/{args.scenario}.zip', args.size) as reader:
        with zipfile.ZipFile(reader) as archive:
            rows = [{'name':x.filename,'bytes':x.file_size,'compressed':x.compress_size,'crc32':f'{x.CRC:08x}'}
                    for x in archive.infolist() if re.search(args.match, x.filename) and not x.is_dir()]
            print(json.dumps({'members':rows,'transferred_bytes':reader.transferred},indent=2))
