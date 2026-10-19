"""Verify received backups, bound retention, and report archive disk use."""
import hashlib
import json
import os
import pwd
import re
import shutil
from datetime import datetime, timezone
from pathlib import Path


def main():
    root = Path('/var/backups/honeypot-center/postgres').resolve()
    root.mkdir(mode=0o700, parents=True, exist_ok=True)
    receiver = pwd.getpwnam('hpbackup')
    os.chown(root, receiver.pw_uid, receiver.pw_gid)
    valid = []
    for directory in sorted(root.iterdir()):
        if not directory.is_dir() or directory.is_symlink() or not re.fullmatch(r'pg-\d{8}T\d{6}Z', directory.name):
            continue
        manifest = directory / 'manifest.json'
        if not manifest.exists():
            continue
        report = json.loads(manifest.read_text())
        for name, metadata in report.items():
            if name != 'honeypot':
                raise ValueError('Unexpected backup database')
            path = directory / (name + '.dump')
            digest = hashlib.sha256()
            with path.open('rb') as source:
                for block in iter(lambda: source.read(1024 * 1024), b''):
                    digest.update(block)
            if digest.hexdigest() != metadata['sha256'] or path.stat().st_size != metadata['bytes']:
                raise ValueError('Backup checksum mismatch: ' + directory.name)
        if report:
            valid.append(directory)
    for old in valid[:-1]:
        assert old.resolve().parent == root
        shutil.rmtree(old)
    usage = shutil.disk_usage(root)
    free_gib = round(usage.free / 1024 ** 3, 2)
    output = {'time': datetime.now(timezone.utc).isoformat(),
              'status': 'critical' if free_gib < 2 or not valid else 'warning' if free_gib < 5 else 'ok',
              'verified_backups': min(1, len(valid)), 'free_gib': free_gib}
    Path('/var/lib/honeypot/backup-inventory.json').write_text(json.dumps(output, indent=2))
    print(json.dumps(output))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
