"""Fingerprint all public tables for a stopped-writer database relocation."""
import argparse
import hashlib
import json
import os
from pathlib import Path

import psycopg
from psycopg import sql


def fingerprint(dsn):
    result = {}
    with psycopg.connect(dsn) as conn:
        conn.execute('SET TRANSACTION ISOLATION LEVEL REPEATABLE READ READ ONLY')
        conn.execute("SET timezone='UTC'")
        conn.execute("SET datestyle='ISO, YMD'")
        tables = conn.execute("SELECT tablename FROM pg_tables WHERE schemaname='public' ORDER BY tablename").fetchall()
        for (table,) in tables:
            keys = conn.execute("""SELECT a.attname FROM pg_index i
                JOIN pg_attribute a ON a.attrelid=i.indrelid AND a.attnum=ANY(i.indkey)
                WHERE i.indrelid=%s::regclass AND i.indisprimary ORDER BY a.attnum""",
                ('public.' + '"' + table + '"',)).fetchall()
            if not keys:
                raise ValueError('Stable primary key required: ' + table)
            query = sql.SQL('COPY (SELECT * FROM {} ORDER BY {}) TO STDOUT').format(
                sql.Identifier(table), sql.SQL(',').join(sql.Identifier(k[0]) for k in keys))
            digest = hashlib.sha256()
            with conn.cursor() as cursor:
                with cursor.copy(query) as stream:
                    for block in stream:
                        digest.update(block)
            count = conn.execute(sql.SQL('SELECT count(*) FROM {}').format(sql.Identifier(table))).fetchone()[0]
            result[table] = {'rows': count, 'sha256': digest.hexdigest()}
            print(json.dumps({'table': table, 'rows': count}), flush=True)
    return result


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--dsn-env', required=True)
    parser.add_argument('--output', required=True)
    parser.add_argument('--compare')
    args = parser.parse_args()
    result = fingerprint(os.environ[args.dsn_env].replace('postgresql+psycopg://', 'postgresql://', 1))
    Path(args.output).write_text(json.dumps(result, indent=2))
    if args.compare:
        expected = json.loads(Path(args.compare).read_text())
        if result != expected:
            raise ValueError('Database contents differ; keep source and do not activate target')
        print(json.dumps({'all_tables_equal': True, 'tables': len(result)}))


if __name__ == '__main__':
    main()
