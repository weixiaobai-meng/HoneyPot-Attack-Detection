"""Create the management schema without starting web servers or schedulers."""
import sys
from pathlib import Path

root = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(root / 'systemwire2'))
from flask import Flask
from config.database import database_url, engine_options
from flask_server.exts import db
from flask_server import models, alert_store

app = Flask('schema_init')
app.config['SQLALCHEMY_DATABASE_URI'] = database_url()
app.config['SQLALCHEMY_ENGINE_OPTIONS'] = engine_options()
db.init_app(app)
with app.app_context():
    db.create_all()
    for table in db.metadata.sorted_tables:
        for index in table.indexes:
            index.create(db.engine, checkfirst=True)
print('Management schema created')
