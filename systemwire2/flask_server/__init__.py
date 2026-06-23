import os
from flask import Flask
from .exts import init_exts
from .views import api
from config.config  import *
# 鑾峰彇椤圭洰鍩虹洰褰?
BASE_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
INSTANCE_DIR = os.path.join(BASE_DIR, 'instance')

def resolve_sqlite_db_path():
    if DB_FILE_PATH:
        return os.path.abspath(os.path.expandvars(DB_FILE_PATH))
    return os.path.join(INSTANCE_DIR, DB_FILE_NAME)

def create_app():
    # 鍒涘缓app
    app = Flask(__name__)
    app.secret_key = FLASK_SECRET_KEY
    app.config['PREFERRED_URL_SCHEME'] = FLASK_HTTP_MODE
    app.config['SESSION_COOKIE_HTTPONLY'] = True
    # app.config['SESSION_COOKIE_SECURE'] = True
    app.config['SESSION_PERMANENT'] = False  # 涓嶆寔涔呭寲
    app.config['SESSION_USE_SIGNER'] = True  # 绛惧悕淇濇姢
    
    # 娉ㄥ唽钃濆浘
    app.register_blueprint(blueprint=api)

    # 閰嶇疆鏁版嵁搴?
    db_uri = f"sqlite:///{resolve_sqlite_db_path()}"
    app.config['SQLALCHEMY_DATABASE_URI'] = db_uri
    app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False  # 绂佺敤瀵硅薄杩借釜
    init_exts(app)  # 鍒濆鍖栨彃浠?db-orm,migrate)
    return app


