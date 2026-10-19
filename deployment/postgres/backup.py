"""Back up the single honeypot database and keep a second server copy."""
import hashlib
import json
import os
import subprocess
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlsplit, unquote


def main():
    root=Path('/var/backups/honeypot-postgres');root.mkdir(mode=0o700,parents=True,exist_ok=True)
    stamp=datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ')
    target=root/('pg-'+stamp);target.mkdir(mode=0o700)
    report={}
    for name,var in [('honeypot','SYSTEMWIRE_DATABASE_URL')]:
        parsed=urlsplit(os.environ[var].replace('postgresql+psycopg://','postgresql://',1))
        env=os.environ.copy()
        env.update(PGHOST=parsed.hostname,PGPORT=str(parsed.port or 5432),PGUSER=unquote(parsed.username),
                   PGPASSWORD=unquote(parsed.password),PGDATABASE=parsed.path.lstrip('/'))
        path=target/(name+'.dump')
        subprocess.run(['pg_dump','--format=custom','--compress=6','--no-owner','--no-acl','--file',str(path)],env=env,check=True)
        path.chmod(0o600)
        subprocess.run(['pg_restore','--list',str(path)],check=True,stdout=subprocess.DEVNULL)
        digest=hashlib.sha256()
        with path.open('rb') as f:
            for block in iter(lambda:f.read(1024*1024),b''):digest.update(block)
        report[name]={'sha256':digest.hexdigest(),'bytes':path.stat().st_size}
    (target/'manifest.json').write_text(json.dumps(report,indent=2))
    destination=os.environ.get('HONEYPOT_BACKUP_DEST','hpbackup@47.239.238.27:postgres/')
    bandwidth = max(1, int(os.environ.get('HONEYPOT_BACKUP_BWLIMIT_KIB', '64')))
    subprocess.run(['rsync','-a','--checksum','--bwlimit='+str(bandwidth),'--chmod=F600,D700','-e',
                    'ssh -i /etc/honeypot/backup_ed25519 -o BatchMode=yes -o StrictHostKeyChecking=yes',
                    str(target),destination],check=True)
    # Only successful generated backup directories are retained/removed here.
    (target/'transferred.ok').write_text(stamp)
    import shutil
    completed=sorted(p for p in root.glob('pg-*') if p.is_dir() and (p/'transferred.ok').exists())
    for old in completed[:-7]:
        shutil.rmtree(old)
    print(json.dumps({'backup':str(target),'copied_offsite':True,'databases':report}))


if __name__=='__main__':
    main()
