import atexit
import os
from flask_apscheduler import APScheduler
from flask_login import LoginManager
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
from sqlalchemy import MetaData
from werkzeug.security import generate_password_hash

from config.config import (
    DB_FILE_NAME,
    DB_FILE_PATH,
    LOCAL_BOOTSTRAP,
    LOCAL_ADMIN_USERNAME,
    LOCAL_ADMIN_PASSWORD,
    LOCAL_AGENT_ID,
    LOCAL_AGENT_NAME,
    LOCAL_AGENT_TOKEN,
    LOCAL_AGENT_IP,
    LOCAL_AGENT_OS,
    LOCAL_AGENT_ARCH,
    LOCAL_JS_SERVER_NAME,
    LOCAL_JS_SERVER_IP,
    LOCAL_DEMO_HONEYFILE,
)

naming_convention = {
    "ix": 'ix_%(column_0_label)s',
    "uq": "uq_%(table_name)s_%(column_0_name)s",
    "ck": "ck_%(table_name)s_%(column_0_name)s",
    "fk": "fk_%(table_name)s_%(column_0_name)s_%(referred_table_name)s",
    "pk": "pk_%(table_name)s"
}

db = SQLAlchemy(metadata=MetaData(naming_convention=naming_convention))
migrate = Migrate()
scheduler = APScheduler()
login_manager = LoginManager()


def init_exts(app):
    db.init_app(app=app)
    migrate.init_app(app=app, db=db, render_as_batch=True)

    if scheduler.running:
        try:
            scheduler.shutdown(wait=False)
        except Exception:
            pass
    scheduler.init_app(app=app)

    with app.app_context():
        init_db(app)
        from flask_server.alert_store import backfill_unified_alerts, ensure_unified_alert_schema

        ensure_unified_alert_schema()
        if _env_flag("SYSTEMWIRE_STARTUP_BACKFILL", default=False):
            backfill_unified_alerts(app)
        else:
            app.logger.info("startup unified alert backfill skipped; set SYSTEMWIRE_STARTUP_BACKFILL=1 to enable")

        if _env_flag("SYSTEMWIRE_STARTUP_HONEYFILE_REPAIR", default=False):
            try:
                from flask_server.views import _repair_all_local_honeyfiles

                repair_result = _repair_all_local_honeyfiles()
                app.logger.info(
                    "startup honeyfile repair finished: repaired=%s skipped=%s",
                    repair_result.get("repaired_count", 0),
                    repair_result.get("skipped_count", 0),
                )
            except Exception as exc:
                app.logger.warning("startup honeyfile repair failed: %s", exc)
        else:
            app.logger.info("startup honeyfile repair skipped; set SYSTEMWIRE_STARTUP_HONEYFILE_REPAIR=1 to enable")
        if LOCAL_BOOTSTRAP:
            bootstrap_local_data(app)
        if not scheduler.running:
            scheduler.start()

    app.scheduler = scheduler
    atexit.register(_shutdown_scheduler)

    login_manager.init_app(app)
    login_manager.login_view = 'login'


def _env_flag(name, default=False):
    value = os.getenv(name)
    if value is None:
        return default
    return value.strip().lower() in ("1", "true", "yes", "on")


def _shutdown_scheduler():
    if scheduler.running:
        try:
            scheduler.shutdown(wait=False)
        except Exception:
            pass


def _db_path(app):
    if DB_FILE_PATH:
        return os.path.abspath(os.path.expandvars(DB_FILE_PATH))
    return os.path.join(app.instance_path, DB_FILE_NAME)


def init_db(app):
    db_path = _db_path(app)
    os.makedirs(os.path.dirname(db_path), exist_ok=True)
    os.makedirs(app.instance_path, exist_ok=True)
    db.create_all()
    _ensure_honeyfile_runtime_columns(db_path)
    db.session.commit()
    app.logger.info("database ready: %s", db_path)


def _ensure_honeyfile_runtime_columns(db_path):
    os.makedirs(os.path.dirname(db_path), exist_ok=True)
    with db.engine.begin() as conn:
        columns = {
            row[1]
            for row in conn.exec_driver_sql('PRAGMA table_info("honeyfiles")').fetchall()
        }
        ddl_statements = []
        if "token_alert_msg" not in columns:
            ddl_statements.append('ALTER TABLE "honeyfiles" ADD COLUMN "token_alert_msg" VARCHAR(255)')
        if "source_file_name" not in columns:
            ddl_statements.append('ALTER TABLE "honeyfiles" ADD COLUMN "source_file_name" VARCHAR(255)')
        if "source_template_name" not in columns:
            ddl_statements.append('ALTER TABLE "honeyfiles" ADD COLUMN "source_template_name" VARCHAR(255)')
        if "source_archive_name" not in columns:
            ddl_statements.append('ALTER TABLE "honeyfiles" ADD COLUMN "source_archive_name" VARCHAR(255)')
        for ddl in ddl_statements:
            conn.exec_driver_sql(ddl)


def bootstrap_local_data(app):
    from flask_server.controller.get_token import getToken
    from flask_server.controller.ms_excel import gen_tokened_excel
    from flask_server.controller.ms_word import gen_tokened_word
    from flask_server.models import User, ClientInfo, Server, Honeyfile

    changed = False

    user = User.query.filter_by(username=LOCAL_ADMIN_USERNAME).first()
    if user is None:
        user = User(
            username=LOCAL_ADMIN_USERNAME,
            password=generate_password_hash(LOCAL_ADMIN_PASSWORD, method='pbkdf2:sha256')
        )
        db.session.add(user)
        changed = True

    probe = ClientInfo.query.filter_by(client_id=LOCAL_AGENT_ID).first()
    if probe is None:
        probe = ClientInfo(client_id=LOCAL_AGENT_ID)
        db.session.add(probe)
        changed = True

    probe.client_name = LOCAL_AGENT_NAME
    probe.ip = LOCAL_AGENT_IP
    probe.hostname = LOCAL_AGENT_NAME
    probe.token = LOCAL_AGENT_TOKEN
    probe.arch = LOCAL_AGENT_ARCH
    probe.ope_sys = LOCAL_AGENT_OS
    probe.status = 'offline'
    probe.registered = 'yes'

    js_server = Server.query.filter_by(company_name=LOCAL_JS_SERVER_NAME).first()
    if js_server is None:
        js_server = Server(company_name=LOCAL_JS_SERVER_NAME, ip_address=LOCAL_JS_SERVER_IP)
        db.session.add(js_server)
        changed = True
    elif js_server.ip_address != LOCAL_JS_SERVER_IP:
        js_server.ip_address = LOCAL_JS_SERVER_IP
        changed = True

    if LOCAL_DEMO_HONEYFILE:
        generate_dir = os.path.abspath(os.path.join(app.root_path, '..', 'Honeyfiles', 'generate'))
        if os.path.isdir(generate_dir):
            sample_name = next((name for name in os.listdir(generate_dir)
                                if os.path.isfile(os.path.join(generate_dir, name))), None)
            if sample_name:
                demo_file = Honeyfile.query.filter_by(name=sample_name).first()
                suffix = sample_name.rsplit('.', 1)
                doc_format = suffix[1].lower() if len(suffix) == 2 else 'bin'
                if demo_file is None:
                    demo_file = Honeyfile(
                        user=LOCAL_ADMIN_USERNAME,
                        name=sample_name,
                        email='local@example.com',
                        message='local-lab-demo',
                        server=LOCAL_JS_SERVER_NAME,
                        token='local-demo-honeyfile',
                        doc_format=doc_format,
                        source=1,
                        honeypoint_name='Local Demo Honeyfile'
                    )
                    db.session.add(demo_file)
                    db.session.flush()
                    changed = True

                token_value = str(demo_file.token or '').strip()
                if not token_value or token_value == 'local-demo-honeyfile' or '/static/img/logo-' not in token_value:
                    err, token_or_msg = getToken(demo_file.email or 'local@example.com', demo_file.message or 'local-lab-demo')
                    if err:
                        app.logger.warning('local demo honeyfile token bootstrap failed for %s: %s', sample_name, token_or_msg)
                    else:
                        demo_file.token = token_or_msg
                        changed = True

                token_url = str(demo_file.token or '').strip()
                sample_path = os.path.join(generate_dir, sample_name)
                if _generated_file_needs_refresh(sample_path, token_url):
                    err, detail = _regenerate_demo_honeyfile(
                        file_path=sample_path,
                        file_name=sample_name,
                        doc_format=doc_format,
                        token_url=token_url,
                        gen_word=gen_tokened_word,
                        gen_excel=gen_tokened_excel,
                    )
                    if err:
                        app.logger.warning('local demo honeyfile refresh failed for %s: %s', sample_name, detail)
                    else:
                        app.logger.info('local demo honeyfile refreshed with live token: %s', sample_name)

    if changed:
        db.session.commit()
        app.logger.info('local bootstrap ready: user=%s agent=%s token=%s', LOCAL_ADMIN_USERNAME, LOCAL_AGENT_ID, LOCAL_AGENT_TOKEN)


def _generated_file_needs_refresh(file_path, token_url):
    if not os.path.isfile(file_path):
        return False
    token_url = str(token_url or '').strip()
    if '/static/img/logo-' not in token_url:
        return False
    try:
        with open(file_path, 'rb') as f:
            return token_url.encode('utf-8') not in f.read()
    except Exception:
        return False


def _regenerate_demo_honeyfile(*, file_path, file_name, doc_format, token_url, gen_word, gen_excel):
    ext = str(doc_format or '').lower()
    try:
        if ext == 'docx':
            code, generated_name = gen_word('', token_url, 0)
        elif ext == 'xlsx':
            code, generated_name = gen_excel('', token_url, 0)
        else:
            return 1, f'unsupported local demo format: {ext}'

        if code:
            return 1, generated_name

        workdir = os.path.dirname(file_path) or os.getcwd()
        generated_path = os.path.join(workdir, generated_name)
        if not os.path.isfile(generated_path):
            return 1, f'generated file missing: {generated_path}'
        if os.path.abspath(generated_path) != os.path.abspath(file_path):
            os.replace(generated_path, file_path)
        return 0, file_path
    except Exception as exc:
        return 1, str(exc)

