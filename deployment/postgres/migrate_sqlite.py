"""Copy a stopped SQLite database into an EMPTY PostgreSQL schema.

The target schema must be created by the application first. No rows are skipped,
no existing target rows are overwritten, and the entire import is transactional.
Passwords are read only from an environment variable. JSONL progress omits data.
"""
import argparse
import hashlib
import json
import os
import re
import sqlite3
from datetime import datetime, timezone
from pathlib import Path
from zoneinfo import ZoneInfo

import psycopg
from psycopg import sql
from psycopg.types.json import Json
from sqlalchemy import create_engine, MetaData


def convert(value, kind):
    if value is None:
        return None
    if kind == 'boolean':
        return bool(value)
    if kind in ('json', 'jsonb'):
        return Json(json.loads(value) if isinstance(value, str) else value)
    if kind.startswith('timestamp') or kind == 'date':
        if isinstance(value, (int, float)):
            return datetime.fromtimestamp(value, ZoneInfo('Asia/Shanghai'))
        value = re.sub(r' m=[+-].*$', '', value)
        value = re.sub(r' ([A-Z]{2,5})$', '', value)
        value = re.sub(r'(\.\d{6})\d+', r'\1', value)
        value = re.sub(r' (?=[+-]\d{4}$)', '', value)
        result = datetime.fromisoformat(value.replace('Z', '+00:00'))
        if result.tzinfo is None:
            result = result.replace(tzinfo=ZoneInfo('Asia/Shanghai'))
        return result
    if kind in ('double precision', 'real', 'numeric'):
        return float(value)
    if isinstance(value, str) and '\x00' in value:
        raise ValueError('NUL in text requires explicit lossless encoding before migration')
    return value


def canonical(values):
    def normalize(value):
        if isinstance(value, Json):
            return value.obj
        if isinstance(value, datetime):
            return value.astimezone(timezone.utc).isoformat(timespec='microseconds')
        return value
    return json.dumps([normalize(v) for v in values], sort_keys=True, ensure_ascii=True,
                      default=str, separators=(',',':')).encode()


def main():
    p = argparse.ArgumentParser()
    p.add_argument('--source', required=True)
    p.add_argument('--dsn-env', required=True)
    p.add_argument('--report', required=True)
    args = p.parse_args()
    dsn = os.environ[args.dsn_env].replace('postgresql+psycopg://', 'postgresql://', 1)
    source = sqlite3.connect('file:' + str(Path(args.source).resolve()) + '?mode=ro', uri=True)
    source.row_factory = sqlite3.Row
    source.execute('BEGIN')
    tables = {r[0] for r in source.execute("SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%'")}
    engine = create_engine(dsn.replace('postgresql://', 'postgresql+psycopg://', 1))
    metadata = MetaData()
    metadata.reflect(engine)
    missing = tables - set(metadata.tables)
    if missing:
        raise ValueError('Missing target tables: ' + ','.join(sorted(missing)))
    report = {'source': str(Path(args.source).resolve()), 'tables': {}}
    with psycopg.connect(dsn, options='-c timezone=Asia/Shanghai') as dest:
        for table in metadata.sorted_tables:
            name = table.name
            if name not in tables:
                continue
            if dest.execute(sql.SQL('SELECT count(*) FROM {}').format(sql.Identifier(name))).fetchone()[0]:
                raise ValueError('Target must be empty: ' + name)
            columns = [r[1] for r in source.execute('PRAGMA table_info("'+name+'")')]
            unknown = set(columns) - set(table.columns.keys())
            if unknown:
                raise ValueError('Unmapped columns in ' + name + ': ' + str(sorted(unknown)))
            types = dict(dest.execute('SELECT column_name,data_type FROM information_schema.columns WHERE table_schema=%s AND table_name=%s', ('public',name)).fetchall())
            quoted = ','.join('"'+c+'"' for c in columns)
            digest = hashlib.sha256()
            normalized_digest = hashlib.sha256()
            count = 0
            primary = [c.name for c in table.primary_key.columns]
            order = ','.join('"'+c+'"' for c in primary) if primary else quoted
            with dest.cursor().copy(sql.SQL('COPY {} ({}) FROM STDIN').format(sql.Identifier(name),sql.SQL(',').join(map(sql.Identifier,columns)))) as copy:
                for row in source.execute('SELECT '+quoted+' FROM "'+name+'" ORDER BY '+order):
                    values = list(row)
                    digest.update(json.dumps(values, ensure_ascii=True, default=str, separators=(',',':')).encode())
                    try:
                        converted = [convert(v,types[c]) for c,v in zip(columns,values)]
                        normalized_digest.update(canonical(converted))
                        copy.write_row(converted)
                    except Exception as exc:
                        raise ValueError('Conversion failed in '+name+' at row '+str(count+1)+': '+type(exc).__name__) from None
                    count += 1
            actual = dest.execute(sql.SQL('SELECT count(*) FROM {}').format(sql.Identifier(name))).fetchone()[0]
            if count != actual:
                raise ValueError('Count mismatch: '+name)
            target_digest = hashlib.sha256()
            with dest.cursor(name='verify_'+name) as verify:
                verify.execute(sql.SQL('SELECT {} FROM {} ORDER BY {}').format(
                    sql.SQL(',').join(map(sql.Identifier,columns)),sql.Identifier(name),
                    sql.SQL(',').join(map(sql.Identifier,primary or columns))))
                for row in verify:
                    target_digest.update(canonical(row))
            if target_digest.digest() != normalized_digest.digest():
                raise ValueError('Content checksum mismatch: '+name)
            for col in table.primary_key.columns:
                seq = dest.execute('SELECT pg_get_serial_sequence(%s,%s)', ('"'+name+'"',col.name)).fetchone()[0]
                if seq:
                    maximum = dest.execute(sql.SQL('SELECT max({}) FROM {}').format(sql.Identifier(col.name),sql.Identifier(name))).fetchone()[0]
                    dest.execute('SELECT setval(%s,%s,%s)',(seq, maximum or 1, maximum is not None))
            report['tables'][name]={'count':count,'source_sha256':digest.hexdigest(),
                                  'normalized_sha256':target_digest.hexdigest(),'verified':True}
            print(json.dumps({'table':name,'rows':count}),flush=True)
        dest.execute('ANALYZE')
    source.close()
    engine.dispose()
    Path(args.report).write_text(json.dumps(report,indent=2),encoding='utf-8')


if __name__ == '__main__':
    try:
        main()
    except psycopg.Error as exc:
        print(json.dumps({'error':type(exc).__name__, 'sqlstate':exc.sqlstate,
                          'table':exc.diag.table_name,'column':exc.diag.column_name}),flush=True)
        raise SystemExit(1)
