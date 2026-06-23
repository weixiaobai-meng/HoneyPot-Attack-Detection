import configparser
import os
from pathlib import Path,PureWindowsPath
import random
import re
import string
import time
import uuid
from flask import jsonify
import sys
import requests
import pytz

from datetime import datetime, timedelta
from config import read_file, time_format_file
from config.config import (
    FLASK_MODE,
    PARTMENT,
    FILE_ALERT_SERVER,
    MANAGE_ADDRESS,
    PARASITIC_ALERT_SERVER,
    API_KEY,
    TIME_FORMAT,
    EMAIL_PERIOD_SECONDS,
    FILE_PERIOD_SECONDS,
    PARASITIC_PERIOD_SECONDS,
    KAFKA_SERVER_ADDRESS,
    HONEYFILE_ALERT_TOPIC,
    HONEYEMAIL_ALERT_TOPIC,
    GATEWAY_SERVER_ADDRESS,
    NACOS_SERVER_ADDRESS,
    LOCAL_ADDRESS,
)

def get_project_root():
    """Get the project root directory."""
    if getattr(sys, 'frozen', False):
        base_path = Path(sys.executable).parent
    else:
        base_path = Path(__file__).parent

    # Search upward for project root markers
    root_markers = ['config.ini', 'config', '.git']

    current_path = base_path
    while current_path != current_path.parent:
        if any((current_path / marker).exists() for marker in root_markers):
            return current_path
        current_path = current_path.parent

    return base_path

project_path = str(get_project_root())
config_path = project_path+"/config.ini"

class Config():
    def __init__(self) -> None:


        self.gateway_addr = GATEWAY_SERVER_ADDRESS
        self.Nacos_addr = NACOS_SERVER_ADDRESS
        self.Local_addr = LOCAL_ADDRESS

        self.Env_mode = FLASK_MODE
        self.Partment = PARTMENT

        self.alert_server_manage_address = MANAGE_ADDRESS
        self.file_alert_server_address = FILE_ALERT_SERVER
        self.parasitic_alert_server_address = PARASITIC_ALERT_SERVER # js/bot base url
        self.api_key = API_KEY
        self.time_format = TIME_FORMAT

        self.pull_Mailcircle = 5
        self.pull_Mailcircle_seconds = EMAIL_PERIOD_SECONDS
        self.pull_Filecircle = 1
        self.pull_Filecircle_seconds = FILE_PERIOD_SECONDS
        self.pull_Parasiticcircle_seconds = PARASITIC_PERIOD_SECONDS
        self.pull_Email_day = 0
        self.pull_File_day = 0

        self.kafka_server_list = [KAFKA_SERVER_ADDRESS]
        self.Kafka_file_topic_list = [HONEYFILE_ALERT_TOPIC]
        self.Kafka_email_topic_list = [HONEYEMAIL_ALERT_TOPIC]


Server_config = Config()




# Register nacos service
def service_register():
    params = {
        "ip": "172.25.0.100",
        "port": 5001,
        "weight": 1,
        "enable": True,
        "healthy": True,
        "ephemeral": True,
        "serviceName": "systemwire",
        "groupName": "DEFAULT_GROUP",
        "clusterName": "DEFAULT",

        "namespaceId": "public",
        "protectThreshold": "0.0",
    }
    url = Server_config.Nacos_addr + "/nacos/v1/ns/instance"
    registerInstance_response = requests.post(url, params=params, timeout=2)
    if registerInstance_response.status_code == 200:
        return 1,registerInstance_response.text
    return 0,registerInstance_response.text



def get_random_string(length):
    letters = (
            string.ascii_letters + string.digits
    )
    result_str = "".join(random.choice(letters) for i in range(length))
    return result_str

# Generate random uint64 id
def generate_uint64_id():
    timestamp = int(time.time())
    random_part = random.randint(0, 999999)
    return (timestamp << 20) | random_part

def random_date(start, end):
    return start + timedelta(
        seconds=random.randint(0, int((end - start).total_seconds())),
        microseconds=random.randint(0, 999000)
    )


def validate_email_account(email):
    """Validate email format.

    Keyword arguments:
    email -- email address
    Return: True if format is invalid
            False if format is valid
    """

    if (
            re.match(r"^[a-zA-Z0-9_-]+@[a-zA-Z0-9_-]+(\.[a-zA-Z0-9_-]+)+$", email) is None
    ):
        return True
    return False


# Username format validation
def validate_username(username):
    """Validate username format.

    Keyword arguments:
    username -- username
    Return: True if format is invalid
            False if format is valid
    """

    pattern = r"^[A-Za-z0-9]{1,16}$"
    if re.match(pattern, username):
        return False
    else:
        return True


# Password format validation
def validate_password(password):
    """Validate password format.

    Keyword arguments:
    password -- password
    Return: True if format is invalid
            False if format is valid
    """

    pattern = r"^[A-Za-z0-9!@#$_&.]{5,16}$"
    if re.match(pattern, password):
        return False
    else:
        return True


# Domain format validation
def validate_domain(server_domain):
    pattern = r"^[a-zA-Z0-9-]+(\.[a-zA-Z0-9-]+)*\.[a-zA-Z]{2,}$"
    if re.match(pattern, server_domain):
        return False
    else:
        return True

# URL validation
def validate_url_format(string):
    pattern = re.compile(r'^(http|https|ftp):\/\/[a-zA-Z0-9\-_]+(\.[a-zA-Z0-9\-_]+)+([\w\-\.,@?^=%&:/~\+#]*['
                         r'\w\-\@?^=%&/~\+#])?$')
    if re.match(pattern, string):
        return True
    else:
        return False


# Time format validation
def validate_email_time_format(timestr, format):
    """Validate time string format."""
    pass
    try:
        datetime.strptime(timestr, format)
        return True
    except ValueError:
        return False

# Validate file path
def validate_path(path_str):
    try:
        if Path(path_str).is_absolute():
            return True
        if PureWindowsPath(path_str).is_absolute():
            return True
        return False
    except Exception:
        return False

# Email time format processing
def timestr_to_datetime(timestr):
    """Convert time string to datetime."""
    if TIME_FORMAT:
        for each in TIME_FORMAT:
            if validate_email_time_format(timestr, each):
                return datetime.strptime(timestr, each)
        return None


# Get honey point network info
def hp_net_info():
    url_get_hp_ip = "http://172.25.0.100:8081/service/instantiation/hp_manage/distinct_field"
    args = {
        "field_name": "hp_ip"
    }
    try:
        response = requests.get(url_get_hp_ip, params=args)
    except Exception as e:
        print(e)
        return 1, e
    ips = response.json()["data"]

    url_get_hp_service = "http://172.25.0.100:8081/service/instantiation/hp_manage/query/detail"

    try:
        service_hp = {}
        for ip in ips:
            args = {"hp_ip": ip}
            response = requests.post(url_get_hp_service, params=args)
            services = response.json()["data"]
            for each in services:
                service_hp[each['server_name']] = [each['ID'], ip]
    except Exception as e:
        print(e)
        return 1, e

    if service_hp is None:
        return 1, "Service is not deployed to the honey point"
    url_get_hp = "http://172.25.0.100:8081/service/instantiation/hp_manage/query"
    args = {
        "page_num": 1,
        "page_size": 100
    }
    response = requests.post(url_get_hp, json=args)
    if response.status_code != 200:
        print("Service info request error")
        return 1, "Service info request error"
    hp_infos = response.json()["data"]["items"]
    if response.json()["code"] != 1:
        print("Base info get error")
        return 1, "Base info get error"
    if response.json()["data"]["total"] == 0:
        return 1, "Result empty"
    ip_net = {}
    for each in hp_infos:
        ip_net[each['hp_ip']] = each['hp_net_id']
    info = {"service_hp": service_hp, "ip_net": ip_net}
    return 0, info


# Get nacos service ip:port
def get_nacos_service_info(service_name):
    """Get service ip:port by nacos service name."""
    nacos_url = Server_config.Nacos_addr + "/nacos/v1/ns/instance/list"
    args = {
        "serviceName": str(service_name)
    }
    try:
        response = requests.get(nacos_url, args,timeout=2)
    except Exception as e:
        print(e)
        return 1, e
    if response.status_code != 200:
        return 1, "Request nacos error"
    host_infos = response.json().get("hosts")
    if host_infos is None or len(host_infos) == 0:
        return 1, "Service not found"
    service_ip = host_infos[0].get("ip")
    service_port = host_infos[0].get("port")
    info = {
        "service_ip": service_ip,
        "service_port": service_port
    }
    return 0, info


# Get base info
def get_base_info():
    if Server_config.Nacos_addr == "":
        base_info = None
        return 0, base_info
    else:
        err, info = get_nacos_service_info("rsng-honey")
        if err:
            return 1, info

        rsng_honey_ip = info["service_ip"]
        rsng_honey_port = info["service_port"]
        url = f"http://{rsng_honey_ip}:{rsng_honey_port}/base"
        try:
            response = requests.get(url, timeout=2)
        except Exception as e:
            return 2, e
        if response.status_code != 200:
            print("Base info request error")
            return 1, "Base info request error"
        base_info = response.json()["data"]
    return 0, base_info


def get_time_bj(date=None):
    if date is None:
        utc_time = datetime.now(pytz.timezone("UTC"))
    else:
        utc_time = date

    utc_time_bj = utc_time.astimezone(pytz.timezone("Asia/Shanghai"))
    return utc_time_bj


def utc_to_local(utc_time):
    utc_time_bj = utc_time.astimezone(pytz.timezone("Asia/Shanghai")).strftime("%Y-%m-%d %H:%M:%S")
    return utc_time_bj


def isIP(str):
    p = re.compile(r'^((25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(25[0-5]|2[0-4]\d|[01]?\d\d?)$')
    if p.match(str):
        return True
    else:
        return False


def getIpFromStr(str):
    ip_match = re.search(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", str)
    if ip_match:
        ip = ip_match.group()
        return ip
    else:
        return None

# User authentication
def user_auth(auth):
    if Server_config.gateway_addr == "":
            return jsonify({"code": 1, "message": "Missing config: [gateway]server_address", "data": {}})
    url_user_info = Server_config.gateway_addr + "/identity/account/info"
    cookies = {"Authorization": auth}
    try:
        response = requests.get(url_user_info, cookies=cookies)
        if response.status_code != 200:
            return 1, f"Request failed:{response.status_code}"
        elif  response.json().get("code") != 1:
            return 1, response.json().get("message")
        return 0, response.json().get("data").get("username")
    except Exception as e:
        return 2, e


if __name__ == "__main__":
    auth = "bafa462870614ed8820b248a5ac33a3b"
    res = user_auth(auth)
    print(res)
