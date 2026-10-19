"""Database configuration shared by Flask, gRPC and offline tools."""
import os
from pathlib import Path

from config.config import DB_FILE_NAME, DB_FILE_PATH


def database_url():
    value = os.environ.get('SYSTEMWIRE_DATABASE_URL', '').strip()
    if value:
        if value.startswith('postgresql://'):
            value = value.replace('postgresql://', 'postgresql+psycopg://', 1)
        if not value.startswith(('postgresql+psycopg://', 'sqlite:///')):
            raise ValueError('Unsupported SYSTEMWIRE_DATABASE_URL scheme')
        return value
    path = (Path(os.path.expandvars(DB_FILE_PATH)).expanduser().resolve() if DB_FILE_PATH
            else Path(__file__).resolve().parents[1] / 'instance' / DB_FILE_NAME)
    return 'sqlite:///' + str(path)


def engine_options():
    if database_url().startswith('sqlite:'):
        return {'connect_args': {'check_same_thread': False}}
    return {'pool_pre_ping': True, 'pool_size': 3, 'max_overflow': 2,
            'pool_recycle': 1800, 'hide_parameters': True,
            'connect_args': {'connect_timeout': 10, 'options': '-c timezone=Asia/Shanghai'}}
