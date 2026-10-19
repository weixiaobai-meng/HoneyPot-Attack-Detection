"""Capacity inspection and verified, non-destructive historical export."""
import argparse
import gzip
import hashlib
import json
import os
import shutil
import uuid
from datetime import datetime, timezone
from pathlib import Path

import psycopg
from psycopg import sql

TABLES = {
    'account_alerts': 'trigger_time', 'trigger_infos': 'trigger_time',
    'device_fingerprints': 'timestamp', 'bot_detections': 'timestamp',
    'alert_events': 'alert_time', 'alert_raw_events': 'created_at',
    'account_alert_info': 'trigger_time', 'agent_monitor_record': 'trigger_time',
}


def dsn(name):
    return os.environ[name].replace('postgresql+psycopg://', 'postgresql://', 1)


def capacity(args):
    usage = shutil.disk_usage(args.disk)
    percent = usage.used / usage.total * 100
    free_gib = usage.free / 1024 ** 3
    state = 'critical' if percent >= 90 or free_gib < 2 else 'warning' if percent >= 80 or free_gib < 5 else 'ok'
    result = {'time': datetime.now(timezone.utc).isoformat(), 'status': state,
              'disk_used_percent': round(percent, 2), 'disk_free_gib': round(free_gib, 2), 'databases': {}}
    for var in ['SYSTEMWIRE_DATABASE_URL']:
        with psycopg.connect(dsn(var)) as conn:
            name, size = conn.execute('SELECT current_database(),pg_database_size(current_database())').fetchone()
            tables = conn.execute("SELECT relname,pg_total_relation_size(relid),n_live_tup,n_dead_tup FROM pg_stat_user_tables ORDER BY pg_total_relation_size(relid) DESC LIMIT 10").fetchall()
            result['databases'][name] = {'bytes':size, 'largest_tables':tables}
    Path(args.output).write_text(json.dumps(result,indent=2),encoding='utf-8')
    print(json.dumps(result))
    return 0 if state == 'ok' else 2


def archive(args):
    table = args.table
    cutoff = datetime.fromisoformat(args.before)
    if cutoff.tzinfo is None:
        raise ValueError('Archive cutoff must include a timezone')
    directory = Path(args.directory)
    directory.mkdir(parents=True,exist_ok=True,mode=0o700)
    batch_id = str(uuid.uuid4())
    final = directory / (table+'-'+batch_id+'.jsonl.gz')
    temporary = final.with_suffix(final.suffix+'.part')
    digest = hashlib.sha256()
    count = 0
    with psycopg.connect(dsn(args.dsn_env)) as conn:
        conn.execute('SET TRANSACTION ISOLATION LEVEL REPEATABLE READ READ ONLY')
        dbname = conn.execute('SELECT current_database()').fetchone()[0]
        with conn.cursor(name='archive_rows') as cursor, gzip.open(temporary,'wb') as output:
            cursor.execute(sql.SQL('SELECT row_to_json(t)::text FROM {} t WHERE {} < %s ORDER BY {}').format(
                sql.Identifier(table),sql.Identifier(TABLES[table]),sql.Identifier(TABLES[table])),(cutoff,))
            for row in cursor:
                line=(row[0]+'\n').encode();output.write(line);digest.update(line);count+=1
    check=hashlib.sha256(); verified=0
    with gzip.open(temporary,'rb') as source:
        for line in source:
            json.loads(line);check.update(line);verified+=1
    if check.digest()!=digest.digest() or verified!=count:
        raise ValueError('Archive verification failed')
    temporary.chmod(0o600);temporary.replace(final)
    report={'batch_id':batch_id,'database':dbname,'table':table,'cutoff':cutoff.isoformat(),
            'rows':count,'sha256':digest.hexdigest(),'path':str(final),'bytes':final.stat().st_size,
            'live_rows_deleted':0}
    with psycopg.connect(dsn('SYSTEMWIRE_DATABASE_URL')) as conn:
        conn.execute('INSERT INTO storage_archive_batches(batch_id,source_database,source_table,cutoff,row_count,archive_path,sha256,archive_bytes,status,verified_at) VALUES(%s,%s,%s,%s,%s,%s,%s,%s,%s,now())',
                     (batch_id,dbname,table,cutoff,count,str(final),digest.hexdigest(),final.stat().st_size,'verified'))
    final.with_suffix('.manifest.json').write_text(json.dumps(report,indent=2),encoding='utf-8')
    print(json.dumps(report))
    return 0


def main():
    parser=argparse.ArgumentParser()
    sub=parser.add_subparsers(dest='command',required=True)
    monitor=sub.add_parser('capacity');monitor.add_argument('--disk',default='/')
    monitor.add_argument('--output',required=True)
    export=sub.add_parser('archive');export.add_argument('--table',choices=TABLES,required=True)
    export.add_argument('--dsn-env',choices=['ALERT_DATABASE_URL','SYSTEMWIRE_DATABASE_URL'],required=True)
    export.add_argument('--before',required=True);export.add_argument('--directory',required=True)
    args=parser.parse_args()
    raise SystemExit(capacity(args) if args.command=='capacity' else archive(args))


if __name__=='__main__':
    main()
