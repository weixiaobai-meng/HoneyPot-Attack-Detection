# 鏁版嵁搴撴ā鍨?
import os
import threading
import time
import uuid
import pytz
from sqlalchemy import ForeignKey, func, event, create_engine, String, Column, JSON
from sqlalchemy.orm import relationship, sessionmaker
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.engine import Engine
from .exts import db, migrate   # 
from flask_login import UserMixin
from config.config import DB_FILE_NAME, DB_FILE_PATH

# 鍒涘缓鏁版嵁搴撳紩鎿庡拰浼氳瘽
# engine = create_engine('sqlite:///tripwire.db')
base_dir = os.path.abspath(os.path.dirname(__file__))   # 鑾峰彇椤圭洰鏍圭洰褰?
database_path = (
    os.path.abspath(os.path.expandvars(DB_FILE_PATH))
    if DB_FILE_PATH
    else os.path.abspath(os.path.join(base_dir, '..', 'instance', DB_FILE_NAME))
) # build the configured sqlite path
engine = create_engine(
    f'sqlite:///{database_path}',
    connect_args={"check_same_thread": False},
)

SessionFactory = sessionmaker(bind=engine, expire_on_commit=False)
session = SessionFactory()
basedir = os.path.abspath(os.path.dirname(__file__))

beijing_tz = pytz.timezone('Asia/Shanghai')


# 璁剧疆鏃跺尯
@event.listens_for(Engine, "connect")
def set_sqlite_pragma(dbapi_connection, connection_record):
    cursor = dbapi_connection.cursor()
    cursor.execute("PRAGMA foreign_keys=ON")  # 寮€鍚閿害鏉?
    # The local Windows lab environment shows repeated on-disk journal I/O
    # failures for SQLite under the instance DB path. MEMORY mode keeps the DB
    # writable here while avoiding corrupting WAL/rollback-journal files.
    cursor.execute("PRAGMA journal_mode=MEMORY")
    cursor.execute("PRAGMA busy_timeout=5000")
    cursor.close()

# 鐢ㄦ埛妯″瀷
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(150), unique=True, nullable=False)
    password = db.Column(db.String(150), nullable=False)
    

class Honeyfile(db.Model):
    __tablename__ = "honeyfiles"
    id = db.Column(db.Integer, autoincrement=True, primary_key=True)
    # id = db.Column(db.String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    user = db.Column(db.String(50), unique=False, nullable=False)
    name = db.Column(db.String(50), unique=True, nullable=False)
    email = db.Column(db.String(50), unique=False, nullable=False)
    message = db.Column(db.String(100), unique=False, nullable=False)
    server = db.Column(db.String(50), unique=False, nullable=False)
    token = db.Column(db.String(200), nullable=False)
    doc_format = db.Column(db.String(50), unique=False, nullable=False)
    created_at = db.Column(db.DateTime(timezone=True), server_default=func.now())
    source = db.Column(db.Integer, unique=False, nullable=False)
    honeypoint_name = db.Column(db.String(50), unique=False, nullable=False)
    token_alert_msg = db.Column(db.String(255), unique=False, nullable=True)
    source_file_name = db.Column(db.String(255), unique=False, nullable=True)
    source_template_name = db.Column(db.String(255), unique=False, nullable=True)
    source_archive_name = db.Column(db.String(255), unique=False, nullable=True)

    deployment = relationship(
        "Filedeploy", backref="honeyfile"
    )  # 涓嶧iledeploy妯″瀷寤虹珛杩炴帴锛屼竴瀵瑰

    def __repr__(self):
        return f"<Honeyfile {self.name}>"

    def to_json(self):
        filename = self.name.rsplit(".",1)[0]
        full_filename_with_tag = filename + "." + self.doc_format  # 甯︽湁闅忔満鏍囩鐨勬枃浠跺悕
        t = filename.split("-")[:-1]
        full_filename_no_tag = filename.rsplit("-",1)[0] + "." + self.doc_format  # 鍘绘帀闅忔満鏍囩鐨勬枃浠跺悕
        return {
            "id": self.id,
            "filename": full_filename_no_tag,
            "filename_tag": full_filename_with_tag,
            "email": self.email,
            "message": self.message,
            "company": self.message.split("-")[0],
            "server": self.server,
            "user": self.user,
            "created_time": self.created_at,
            "doc_format": self.doc_format,
            "token": self.token,
            "source": self.source,
            "honeypoint_name": self.honeypoint_name,
            "token_alert_msg": self.token_alert_msg,
            "source_file_name": self.source_file_name,
            "source_template_name": self.source_template_name,
            "source_archive_name": self.source_archive_name,
        }


# 瀹氫箟浜嬩欢鐩戝惉鍣?
@event.listens_for(Honeyfile, "before_delete")
def before_delete_listener(mapper, connection, target):
    if target.deployment:  # 濡傛灉File宸茬粡閮ㄧ讲鍒欑姝㈠垹闄?
        raise ValueError(
            "HoneyFile has associated deployment. Deletion is not allowed."
        )


class Filedeploy(db.Model):
    __tablename__ = "filedeploy"
    id = db.Column(db.Integer, autoincrement=True, primary_key=True)
    honeypoint_id = db.Column(db.Integer, ForeignKey("honeyfiles.id", ondelete="RESTRICT"), nullable=False)
    user = db.Column(db.String(50), unique=False, nullable=False)
    deploy_type = db.Column(db.Integer, unique=False, nullable=False)  # 閮ㄧ讲绫诲瀷锛?锛氶儴缃插埌缃戠粶铚滅偣 2锛氶儴缃插埌涓绘満
    hostname = db.Column(db.String(100), unique=False, nullable=False, index=True)
    host_id = db.Column(db.String(100), unique=False, nullable=True)  # 鏈嶅姟id銆佷富鏈篿d
    host_ip = db.Column(db.String(100), unique=False, nullable=True)  # ip
    network_id = db.Column(db.String(100), unique=False, nullable=True)  # 缃戠粶id(閮ㄧ讲鍒扮綉缁滆湝鐐规椂鍙负绌?
    path = db.Column(db.String(100), unique=False, nullable=False)
    ope_sys = db.Column(db.String(50), unique=False, nullable=False)
    status = db.Column(db.Integer, unique=False, nullable=False)
    deploy_at = db.Column(db.DateTime(timezone=True), server_default=func.now())

    def __repr__(self):
        return f"<Filedeploy {self.id}>"

    def to_json(self):
        return {
            "id": self.id,
            "honeypoint_id": self.honeypoint_id,
            "user": self.user,
            "deploy_type": self.deploy_type,
            "hostname": self.hostname,
            "host_id": self.host_id,
            "host_ip": self.host_ip,
            "network_id": self.network_id,
            "path": self.path,
            "ope_sys": self.ope_sys,
            "status": self.status,
            "deploy_at": self.deploy_at,
        }


class Honeyaccount(db.Model):
    __tablename__ = "honeyaccount"
    id = db.Column(db.Integer, autoincrement=True, primary_key=True)
    # id = db.Column(db.String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    username = db.Column(db.String(50), unique=False, nullable=False)
    password = db.Column(db.String(50), unique=False, nullable=False)
    honeypot = db.Column(db.String(50), unique=False, nullable=False)
    created_at = db.Column(db.DateTime(timezone=True), server_default=func.now())
    user = db.Column(db.String(50), unique=False, nullable=False)
    honeypoint_name = db.Column(db.String(50), unique=False, nullable=False)
    position = db.Column(db.String(100), unique=False, nullable=True)
    function = db.Column(db.String(50), unique=False, nullable=False)

    def __repr__(self):
        return f"<Honeyaccount {self.username}>"

    def to_json(self):
        return {
            "id": self.id,
            "username": self.username,
            "password": self.password,
            "honeypot": self.honeypot,
            "user": self.user,
            "created_time": self.created_at,
            "honeypoint_name": self.honeypoint_name,
            "position": self.position,
            "function": self.function,
        }


class Honeyemail(db.Model):
    __tablename__ = "honeyemail"
    id = db.Column(db.Integer, autoincrement=True, primary_key=True)
    server = db.Column(db.String(60), unique=False, nullable=False)
    username = db.Column(db.String(50), unique=True, nullable=False)
    password = db.Column(db.String(50), unique=False, nullable=False)
    protocol = db.Column(db.String(50), unique=False, nullable=False)
    email_count = db.Column(db.Integer, unique=False, nullable=False)
    pull_cycle = db.Column(db.Integer, unique=False, nullable=False, default=10)
    last_receive_state = db.Column(db.String(100), unique=False, nullable=True)
    last_receive_count = db.Column(db.Integer, unique=False, nullable=False)
    last_receive_time = db.Column(db.DateTime(timezone=True))
    created_at = db.Column(db.DateTime(timezone=True), server_default=func.now())

    email = relationship("EmailInfo", backref="account", cascade='all, delete', passive_deletes=True)  # 涓嶦mailInfo妯″瀷寤虹珛杩炴帴锛屼竴瀵瑰

    def __repr__(self):
        return f"<Honeyemail {self.username}>"

    def to_json(self):
        return {
            "id": self.id,
            "server": self.server,
            "username": self.username,
            "password": self.password,
            "email_count": self.email_count,
            "last_receive_count": self.last_receive_count,
            "last_receive_time": self.last_receive_time,
            "last_receive_state": self.last_receive_state,
            "pull_cycle": self.pull_cycle,
            "protocol": self.protocol,
            "created_time": self.created_at,
        }


class EmailInfo(db.Model):
    __tablename__ = "EmailInfo"
    id = db.Column(db.Integer, autoincrement=True, primary_key=True)
    account_id = db.Column(db.Integer, ForeignKey("honeyemail.id", ondelete="CASCADE"))
    # account_id = db.Column(db.Integer, nullable=False)
    server = db.Column(db.String(60), unique=False, nullable=False)
    username = db.Column(db.String(50), unique=False, nullable=False)
    sender = db.Column(db.String(50), unique=False, nullable=False)
    subject = db.Column(db.String(50), unique=False, nullable=True)
    receive_time = db.Column(db.DateTime(timezone=True), unique=False, nullable=False)
    email_type = db.Column(db.String(30), unique=False, nullable=True)
    header = db.Column(db.String(30), unique=False, nullable=True)
    email_id = db.Column(db.Integer, unique=False, nullable=True)

    def __repr__(self):
        return f"<EmailInfo {self.username}>"

    def to_json(self):
        return {
            "server": self.server,
            "account": self.username,
            "account_id": self.account_id,
            "sender": self.sender,
            "subject": self.subject,
            "time": self.receive_time,
            # "time_fmt": self.receive_time.strftime("%Y-%m-%d %H:%M:%S"),
            "type": self.email_type,
            "header": self.header,
            "email_id": self.email_id,
        }


# 鏌ヨ鏃堕棿璁板綍琛?
class LastQueryTime(db.Model):
    __tablename__ = "LastQueryTime"
    id = db.Column(db.Integer, autoincrement=True, primary_key=True)
    # id = db.Column(db.String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    query_type = db.Column(db.String(30), unique=False, nullable=False)
    query_time = db.Column(db.DateTime(timezone=True), unique=False, nullable=False)

    def __repr__(self):
        return f"<LastQueryTime {self.id}>"

    def to_json(self):
        return {
            "id": self.id,
            "query_time": self.query_time,
            "query_type": self.query_type,
        }


# 鏂囦欢鍛婅淇℃伅
class FileAlertInfo(db.Model):
    __tablename__ = "FileAlertInfo"
    id = db.Column(db.Integer, autoincrement=True, primary_key=True)
    # id = db.Column(db.String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    # deploy_id = db.Column(db.Integer, unique=False, nullable=False)
    trigger_time = db.Column(db.DateTime(timezone=True), unique=False, nullable=False)
    alert_message = db.Column(db.String(100), unique=False, nullable=True)
    # alert_address = db.Column(db.String(100), unique=False, nullable=True)
    report_ip = db.Column(db.String(100), unique=False, nullable=True)
    report_agent = db.Column(db.String(100), unique=False, nullable=True)
    token = db.Column(db.String(200), unique=False, nullable=False)

    def __repr__(self):
        return f"<FileAlertInfo {self.id}>"

    def to_json(self):
        return {
            "id": self.id,
            "alert_time": self.trigger_time,
            "alert_message": self.alert_message,
            "description": self.alert_message,
            "reportIp": self.report_ip,
            "reportAgent": self.report_agent,
            "token": self.token
        }


class AccountAlertInfo(db.Model):
    __tablename__ = "account_alert_info"
    id = db.Column(db.Integer, autoincrement=True, primary_key=True)
    trigger_time = db.Column(db.DateTime(timezone=True), unique=False, nullable=False)
    report_time = db.Column(db.DateTime(timezone=True), server_default=func.now())
    src_ip = db.Column(db.String(100), unique=False, nullable=True)
    src_port = db.Column(db.String(20), unique=False, nullable=True)
    dst_ip = db.Column(db.String(100), unique=False, nullable=True)
    dst_port = db.Column(db.String(20), unique=False, nullable=True)
    username = db.Column(db.String(100), unique=False, nullable=True)
    password = db.Column(db.String(255), unique=False, nullable=True)
    client_version = db.Column(db.String(255), unique=False, nullable=True)
    protocol = db.Column(db.String(50), unique=False, nullable=False, default="ssh")
    message = db.Column(db.String(255), unique=False, nullable=True)
    raw_event = db.Column(db.JSON, unique=False, nullable=True)

    def __repr__(self):
        return f"<AccountAlertInfo {self.id}>"

    def to_json(self):
        return {
            "id": self.id,
            "alert_time": self.trigger_time,
            "trigger_time": self.trigger_time,
            "report_time": self.report_time,
            "src_ip": self.src_ip,
            "src_port": self.src_port,
            "dst_ip": self.dst_ip,
            "dst_port": self.dst_port,
            "username": self.username,
            "password": self.password,
            "client_version": self.client_version,
            "protocol": self.protocol,
            "message": self.message,
            "raw_event": self.raw_event,
        }


# 鏂囦欢绫诲瀷瀛楀吀琛?
class FileTypeDict(db.Model):
    __tablename__ = "file_type_dict"
    id = db.Column(db.Integer, autoincrement=True, primary_key=True, nullable=False)
    file_type = db.Column(db.String(50), unique=True, nullable=False)  # 鏂囦欢绫诲瀷(docx,xlsx,exe)
    file_type_cn = db.Column(db.String(50), unique=True, nullable=False)  # 鏂囦欢绫诲瀷涓枃鍚?Word鏂囨。,Excel琛ㄦ牸,鍙墽琛屾枃浠?
    description = db.Column(db.String(100), unique=False, nullable=True)  # 鏂囦欢绫诲瀷鎻忚堪

    def __repr__(self):
        return f"<FileTypeDict {self.fileType}>"

    def to_json(self):
        return {
            "id": self.id,
            "fileType": self.file_type,
            "description": self.description
        }

# client绔俊鎭?
class ClientInfo(db.Model):
    __tablename__ = "agent_client_info"
    id = db.Column(db.Integer, primary_key=True)
    client_id = db.Column(db.String(50), unique=False, nullable=True)
    client_name = db.Column(db.String(50), unique=False, nullable=True)
    ip = db.Column(db.String(50), unique=False, nullable=True)                             # 瀹㈡埛绔疘P
    hostname = db.Column(db.String(50), unique=False, nullable=True)                       # 瀹㈡埛绔悕绉?
    token = db.Column(db.String(50), unique=False, nullable=False)                           # token
    arch = db.Column(db.String(50), unique=False, nullable=False)                           # 鏋舵瀯
    ope_sys = db.Column(db.String(50), unique=False, nullable=False)                        # 瀹㈡埛绔搷浣滅郴缁?
    status = db.Column(db.String(50), unique=False, nullable=False)                         # 瀹㈡埛绔姸鎬?
    register_time = db.Column(db.DateTime(timezone=True), unique=False)     # 娉ㄥ唽鏃堕棿
    last_beat_time = db.Column(db.DateTime(timezone=True), unique=False)    # 鏈€鍚庡績璺虫椂闂?
    registered = db.Column(db.String(10), unique=False)
    def __repr__(self):
        return f"<ClientInfo {self.id}>"

    def to_json(self):
        # register_time_beijing = self.register_time.astimezone(beijing_tz)
        return {
            "id": self.id,
            "client_id":self.client_id,
            "client_name":self.client_name,
            "ip": self.ip,
            "hostname": self.hostname,
            "ope_sys": self.ope_sys,
            "status": self.status,
            "register_time": self.register_time,
            "last_beat_time": self.last_beat_time,
            "arch": self.arch,
            "token": self.token,
            "registered": self.registered
        }
        
# Agent鎿嶆帶鏃ュ織
class AgentControlLog(db.Model):
    __tablename__ = "agent_control_log"
    id = db.Column(db.Integer, primary_key=True)                                    # 璁板綍id
    client_id = db.Column(db.String(50), unique=False, nullable=False)              # 琚搷浣滅殑Agent鐨刬d
    operate_type = db.Column(db.String(50), unique=False, nullable=False)           # 鎿嶄綔绫诲瀷(濡俢reate/delete/cmd)
    operate_id = db.Column(db.BigInteger, unique=False, nullable=False)             # 鎿嶄綔id
    detail = db.Column(db.JSON, unique=False, nullable=True)                        # 缁嗚妭淇℃伅
    success = db.Column(db.Boolean, unique=False, nullable=True)                    # 鏄惁鎴愬姛
    result = db.Column(db.String(50), unique=False, nullable=True)                  # 缁撴灉
    created_at = db.Column(db.DateTime(timezone=True), server_default=func.now())   # 鎿嶄綔鏃堕棿
    finish_at = db.Column(db.DateTime(timezone=True))                               # 瀹屾垚鏃堕棿
    delay = db.Column(db.Float,nullable=True)                                       # 鑺辫垂鏃堕棿
    
    def __reduce__(self):
        return f"AgentControlLog {self.id}"
    
    def to_json(self):
        created_at = self.created_at.astimezone(beijing_tz) if self.created_at else None
        finish_at = self.finish_at.astimezone(beijing_tz) if self.finish_at else None
        return {
            "id":self.id,
            "client_id":self.client_id,
            "operate_type":self.operate_type,
            "operate_id":self.operate_id,
            "detail":self.detail,
            "success":self.success,
            "result":self.result,
            "created_at":created_at,
            "finish_at":finish_at,
            "delay":self.delay
        }
# 鐩戞帶璁板綍
class MonitorAlert(db.Model):
    __tablename__ = "agent_monitor_record"
    id = db.Column(db.Integer, primary_key=True)
    client_id = db.Column(db.String(50), nullable=False)                    # 瀹㈡埛绔疘D
    ip = db.Column(db.String(50), nullable=True)                            # ip
    hostname = db.Column(db.String(50), unique=False, nullable=True)        # 涓绘満鍚?
    proctitle = db.Column(db.JSON, unique=False, nullable=True)             # 杩涚▼鍚?
    cwd = db.Column(db.JSON, unique=False, nullable=True)                   # 褰撳墠宸ヤ綔鐩綍
    syscall = db.Column(db.JSON, unique=False, nullable=True)               # 绯荤粺璋冪敤
    path = db.Column(db.JSON, unique=False, nullable=True)                  # 鏂囦欢璺緞
    trigger_time = db.Column(db.DateTime(timezone=True), unique=False, nullable=False)      # 瑙﹀彂鏃堕棿
    report_time = db.Column(db.DateTime(timezone=True), server_default=func.now())          # 涓婃姤鏃堕棿
    
    def __repr__(self):
        return f"<MonitorRecord {self.id}>"
    
    def to_json(self):
        return {
            "id": self.id,
            "ip": self.ip,
            "client_id": self.client_id,
            "trigger_time": self.trigger_time.astimezone(beijing_tz),
            "report_time": self.report_time.astimezone(beijing_tz),
            "proctitle": self.proctitle,
            "cwd": self.cwd,
            "syscall": self.syscall,
            "path": self.path
        }
    
# # 鑷搴忓垪鍙?
# counter = 0
# counter_lock = threading.Lock()

# @event.listens_for(Filedeploy, 'before_insert')
# @event.listens_for(FileAlertInfo, 'before_insert')
# @event.listens_for(EmailInfo, 'before_insert')
# @event.listens_for(Honeyfile, 'before_insert')
# @event.listens_for(Honeyemail, 'before_insert')
# @event.listens_for(Honeyaccount, 'before_insert')
# @event.listens_for(LastQueryTime, 'before_insert')
# def generate_snowflake_id(mapper, connection, target):
#     global counter
#     with counter_lock:
#         counter += 1
#         if counter > 9999:
#             counter = 0
#     timestamp = int(time.time() * 1000)  # 鑾峰彇褰撳墠鏃堕棿鐨勬绉掔骇鏃堕棿鎴?
#     unique_id = f"{timestamp}{counter:04d}"  # 鑷搴忓垪鍙疯ˉ闆跺埌4浣?
#     target.id = unique_id


# 璺緞铚滅偣
class Honeyurl(db.Model):
    __tablename__ = "honeyurl"
    id = db.Column(db.Integer, autoincrement=True, primary_key=True, nullable=False)
    url = db.Column(db.String(100), unique=False, nullable=False)
    
    def __repr__(self):
        return f"<Honeyurl {self.url}>"
    
    def to_json(self):
        return {
            "id": self.id,
            "url": self.url
        }
        
# 璺緞铚滅偣鍛婅淇℃伅
class UrlAlertInfo(db.Model):
    __tablename__ = "url_alert_info"
    id = db.Column(db.Integer, autoincrement=True, primary_key=True, nullable=False)
    honeypoint_id = db.Column(db.Integer, nullable=True)
    url= db.Column(db.String(100), unique=False, nullable=False)
    trigger_time = db.Column(db.DateTime(timezone=True), unique=False, nullable=False)
    report_time = db.Column(db.DateTime(timezone=True), server_default=func.now()) 
    src_ip = db.Column(db.String(100), unique=False, nullable=False)
    dst_ip = db.Column(db.String(100), unique=False, nullable=True)
    fingerprint = db.Column(db.String(100), unique=False, nullable=True)
    info = db.Column(db.JSON, unique=False, nullable=True)
    
    def __repr__(self):
        return f"<UrlAlertInfo {self.id}>"
    
    def to_json(self):
        return {
            "id": self.id,
            "honeypoint_id": self.honeypoint_id,
            "time": self.trigger_time,
            "url": self.url,
            "trigger_time": self.trigger_time,
            "report_time": self.report_time,
            "src_ip": self.src_ip,
            "dst_ip": self.dst_ip,
            "fingerprint": self.fingerprint,
            "info": self.info
        }
        

class Server(db.Model):
    __tablename__ = "servers"
    
    id = db.Column(db.Integer, autoincrement=True, primary_key=True)
    company_name = db.Column(db.String(100), nullable=False)  # 鍏徃鍚嶇О
    ip_address = db.Column(db.String(50), nullable=False)    # IP鍦板潃
    
    def __repr__(self):
        return f"<Server {self.company_name} - {self.ip_address}>"
    
    def to_json(self):
        return {
            "id": self.id,
            "company_name": self.company_name,
            "ip_address": self.ip_address
        }

