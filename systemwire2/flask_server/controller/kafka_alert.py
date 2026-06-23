import json
import random
import string
from flask import current_app
import requests
import urllib3
import argparse

from datetime import timedelta
from urllib.parse import urlparse
from kafka import KafkaProducer,errors as kafka_errors
from kafka.errors import NoBrokersAvailable
from flask_server.utils.common import Server_config, get_base_info, get_time_bj
from flask_server.models import *

urllib3.disable_warnings()
# 指定日志文件路径
log_file = '../../data/time_query_emailinfo.log'
producer_list = []

def kafka_init(Kafka_server):
    """
    初始化Kafka生产者
    
    Args:
        kafka_server: Kafka服务器地址，例如 'localhost:9092'
        
    Returns:
        Tuple[bool, Union[KafkaProducer, str]]: 
        - 成功返回 (True, producer实例)
        - 失败返回 (False, 错误信息)
    """
    # print("Init Kafka Producer...")
    # for index, Kafka_server in enumerate(Server_config.kafka_server_list):
    try:
        # print(f"[{index}]Kafka_server:", Kafka_server)
        producer = KafkaProducer(
            bootstrap_servers=Kafka_server,             # kafka服务器
            value_serializer=lambda m: json.dumps(m, ensure_ascii=False).encode(),  # json序列化
            request_timeout_ms=20000,                   # 超时时间
            retries=3                                   # 重连尝试
            )
        # 验证连接
        if not producer.bootstrap_connected():
            return False, f"尝试连接{Kafka_server}失败"
        producer_list.append(producer)
    # except NoBrokersAvailable as e:
    #     # print(f"[ERROR] Failed to connect to Kafka broker: {e}")
    #     return False, str(e)
    # except Exception as e:
    #     # print(f"[ERROR ]Kafka-Producer[{len(producer_list) + 1}] 创建失败:", str(e))
    #     return False, str(e)
    except kafka_errors.NoBrokersAvailable as e:
        return False, f"No brokers available: {str(e)}"
    except kafka_errors.KafkaTimeoutError as e:
        return False, f"Connection timeout: {str(e)}"
    except Exception as e:
        return False, f"Unexpected error: {str(e)}"
    return True, "success"
    


# Kafka消息推送回调函数
def on_send_success(record_metadata):
    pass
    # print('Message sent successfully.')
    # print('Topic:', record_metadata.topic)
    # print('Partition:', record_metadata.partition)
    # print('Offset:', record_metadata.offset)


def on_send_error(excp):
    print('Error while sending message:', str(excp))


# 文件告警上报
def send_alert_file(last_push_time):
    if len(producer_list) == 0:
        return 1, "kafka producer 列表为空"
        pass
    if last_push_time is None:
        last_push_time = get_time_bj() - timedelta(days=7)
    current_time = get_time_bj()
    current_time_str = current_time.strftime("%Y-%m-%d %H:%M:%S")

    # 获取蜜点系统基本信息
    err, base_info = get_base_info()
    if err:
        return 2, base_info
    if base_info is None or base_info == "":  # 未获取到蜜点信息
        base_info = {"companyId": "defalult", "id": "null", "nodeUrl": "null"}
    # 查询数据库
    try:  # 联查条件
        # query = session.query(FileAlertInfo, Honeyfile) \
        #        .filter(FileAlertInfo.trigger_time > last_query_time) \
        #        .join(Honeyfile, FileAlertInfo.token == Honeyfile.token)
        # print(query.all())
        # current_app.logger.info(f"last_query_time:{last_query_time}")
        
        alerts = db.session.query(FileAlertInfo, Honeyfile, Filedeploy) \
            .filter(FileAlertInfo.trigger_time > last_push_time) \
            .join(Honeyfile, FileAlertInfo.token == Honeyfile.token) \
            .join(Filedeploy, Honeyfile.id == Filedeploy.honeypoint_id) \
            .group_by(FileAlertInfo.id)
        
        # print("alert count:", alerts.count())
    except Exception as e:
        # print(e)
        return 1, e

    # print(f"Get from local: {alerts.count()}")

    messages = []
    count = 0
    for file_alert_info, honeyfile, file_deploy in alerts:
        info = {
            "companyId": base_info.get('companyId'),
            'nodeId': base_info.get('id'),  # 蜜点系统id
            'hostId': file_deploy.host_id,  # 被保护主机id
            # 'hostId' : 101,  # 被保护主机id
            'hostIP': file_deploy.host_ip,  # 被保护主机ip
            # 'hostIP' : "10.10.100.49",  # 被保护主机ip
            'networkId': file_deploy.network_id,  # 被保护主机所属子网id
            "filePoint": {
                "deployService": file_deploy.hostname,
                "deployLocation": file_deploy.path,
                "fileName": honeyfile.name,
                "fileType": honeyfile.doc_format.replace("\\", "\\\\"),
                "srcFile": honeyfile.source,
                "reportEmail": honeyfile.email,
                "description": honeyfile.message,
                "creator": honeyfile.user,
                "createTime": honeyfile.created_at.strftime("%Y-%m-%d %H:%M:%S"),
            },
            "SrcName": honeyfile.name,
            "partment": Server_config.Partment,  # 部门
            "honeyPointIP": urlparse(base_info['nodeUrl']).hostname,
            'honeyPointNode': base_info.get('name'),  # 蜜点名称
            "honeyPointName": honeyfile.name,  # 蜜点名称
            "trigger_time": file_alert_info.trigger_time.strftime("%Y-%m-%d %H:%M:%S"),
            "reportIP": file_alert_info.report_ip,  # 攻击者IP
            "attackIP": file_alert_info.report_ip,  # 攻击者IP
            # 'deployService' : "172.25.0.100",
            'deployService': urlparse(base_info['nodeUrl']).hostname,
            "description": file_alert_info.alert_message,  # 告警描述
            "nodeType": "蜜点",
            "honeyType": "文件蜜点",
            "time": current_time_str,
            "honeyNetworkType": "out",  # 蜜点类型: 内/外蜜点
            "sub_device_type":"外蜜点",
            "level": 500,  # 告警等级 100 300 500
            "attackType": "1",  # 攻击类型
        }
        if file_deploy.deploy_type ==1 :
            info["deployType"] = "Host" # 部署目标类型：网络蜜点，真实设备
        elif file_deploy.deploy_type ==2:
            info["deployType"] = "服务绊线"
        else:
            info["deployType"] = "手动部署"
        messages.append(info)

        # 发送消息
        try:
            # print("Send message tp:")
            for index, producer in enumerate(producer_list):
                print(f"Push to:producer{index}")
                producer.send(Server_config.Kafka_file_topic_list[index], value=info)
                count = count + 1
        except Exception as e:
            # print(e)  # 其他出错
            return 1, e
    for producer in producer_list:
        producer.flush()
        # producer.close()
    return 0, count



# 邮箱告警上报
def send_alert_email(last_query_time):
    # 获取蜜点系统基本信息
    err, base_info = get_base_info()
    if err:
        return 1, base_info
    if base_info is None or base_info == "":  # 未获取到蜜点信息
        base_info = {"companyId": "null", "id": "null", "nodeUrl": "null"}
    if last_query_time is None:
        last_query_time = get_time_bj() - timedelta(days=30)
    # 查询数据库
    email_infos = (EmailInfo.query
                   # .filter_by(email_type="pfish")
                   .filter(EmailInfo.receive_time > last_query_time)
                   .all()
                   )
    messages = []
    for info in email_infos:
        if '<' in info.sender or '>' in info.sender:  # 邮箱地址格式化: xxx <123@qq.com>
            srcEmail = info.sender.split("<")[1].split(">")[0]
        else:
            srcEmail = info.sender
        if info.email_type == "pfish":
            level = 500
        else:
            level = 100
        info = {
            "companyId": base_info.get('companyId'),
            'nodeId': base_info.get('id'),  # 蜜点系统id
            "honeyPointIP": "蜜点ip",  # 蜜点系统ip
            "honeyPointNode": base_info.get('id'),  # 蜜点系统节点id
            "emailService": info.server,
            "emailAccount": info.username,
            "emailTitle": info.subject,
            "emailHeader": info.header,
            "riskClassification": info.email_type,
            "srcEmail": srcEmail,
            "time": get_time_bj().strftime("%Y-%m-%d %H:%M:%S"),
            "countermeasures": "no",
            "nodeType": "蜜点",
            "honeyType": "邮件蜜点",
            "level": level,
            "attackType": "2"
        }
        messages.append(info)
        # current_app.logger.info(f"[Kafka] 开始推送第{len(messages)}条消息")
        try:
            for index, producer in enumerate(producer_list):
                # current_app.logger.info(f"[Kafka] 推送文件告警消息至:{producer}")
                producer.send(Server_config.Kafka_email_topic_list[index], value=info)
        except Exception as e:
            # print(e)
            return 1, e
        
    current_app.logger.info(f"[Kafka] 本次总推送{len(messages)}条文件告警")
    return 0, len(messages)

# 检查蜜阵是否存在告警类型
def check_alert_dict(dictType, dictCode):
    """
    判断字典库中是否存在指定的字典数据
    """
    if dictType is None:
        return 1, "dictType is None"
    url_search = "http://172.25.0.100:18769/honey/sysDict/data/list"  # 查询字典数据
    args = {
        "pageIndex": 1,
        "pageSize": 20,
        "dictType": dictType
    }
    try:
        response = requests.get(url_search, params=args)
    except Exception as e:
        print(e)
        return 1, e
    if response.status_code != 200:
        print("Request error")
        return 1, "Request error"
    if response.json()["code"] != 1:
        print(response.json()["message"])
        return 1, "Request error"
    data = response.json()["data"]
    if data['total'] == 0:
        return 1, "No data found"
    items = data['items']
    for item in items:
        if item['dictCode'] == dictCode:
            return 0, item
    return 1, "No data found"


# 插入字典数据
def insert_alert_dict(data):
    """
    data = {
      "dictCode": "string",
      "dictType": "string",
      "dictCnCode": "string",
      "description": "string",
      "param": "string",
      "parentId": 0
    }
    """
    url_insert = "http://172.25.0.100:18769/honey/sysDict/data"
    if data.get("dictType") is None or data.get("dictCode") is None or data.get("dictCnCode") is None or data.get(
            "description") is None or data.get("parentId") is None:
        return 1, "Parameter error"
    try:
        response = requests.post(url_insert, json=data)
    except Exception as e:
        print(e)
        return 1, e
    if response.status_code != 200:
        print("Request error")
        return 1, "Request error"
    if response.json()["code"] != 1:
        print(response.json()["message"])
        return 1, "Request error"
    return 0, response.json()["message"]

# 定义回调函数
def on_send_success(record_metadata):
    print(f"消息发送成功: 主题: {record_metadata.topic}, 分区: {record_metadata.partition}, 偏移: {record_metadata.offset}")
    
def on_send_error(excp):
    print(f"消息发送失败: {excp}")
    
# 生成随机字符串
def random_string(length=8):
    return ''.join(random.choices(string.ascii_letters + string.digits, k=length))

# 生成随机IP地址
def random_ip():
    return '.'.join(str(random.randint(0, 255)) for _ in range(4))

# 生成随机时间
def random_time(start=None):
    if not start:
        start = datetime.now() - timedelta(days=7)
    end = datetime.now()
    return start + (end - start) * random.random()

# 生成文件告警测试数据
def kafka_file_test(num,isRealTime=False):
    # 预定义列表
    protected_host_ips = ['10.30.27.250', '10.23.255.251', '172.18.144.180']
    deploy_locations = ['C:\\User\\user\\Desktop', 'D:\\内部文件', 'E:\\Documents','D:\\办公',  'E:\\Documents']
    file_names = ['2024工程项目合作协议.docx', 
                  '采购安装合同书(待签署).docx', 
                  '关于2024年内部岗位优化的通知.docx',
                  '年度收入报表(项目制).xlsx',
                  '商务合作协议书.docx',
                  '工伤事故一次性赔偿协议书.docx',
                  '机场服务管理方案-2023年制.docx',
                  '职务侵占罪和非国家工作人员受贿罪.docx'
                  ]
    honeyPointSystemIP = "10.30.31.30"
    count = 0
    for index in range(num):
        onec_host_ip = random.choice(protected_host_ips)
        onece_location = random.choice(deploy_locations)
        onece_filename = random.choice(file_names)
        once_file_type = onece_filename.split(".")[-1]
        onece_src_ip = random_ip()
        onece_creat_time = random_time()
        if isRealTime:
            onece_trigger_time = datetime.now()
        else:
            onece_trigger_time = random_time(onece_creat_time)
        info = {
                "companyId": "null",
                'nodeId': "null",  # 蜜点系统id
                "deployType": "Host",  # 部署目标类型：网络蜜点，真实设备
                'hostId': "",  # 被保护主机id
                'hostIP': random.choice(protected_host_ips),  # 被保护主机ip
                'networkId': "",  # 被保护主机所属子网id
                "filePoint": {
                    "deployService": honeyPointSystemIP,        # 部署服务器
                    "deployLocation": onece_location,
                    "fileName": onece_filename,
                    "fileType": once_file_type,
                    "srcFile": 1,
                    "reportEmail": "",
                    "description": onece_filename+"-"+onec_host_ip+"-"+onece_location,
                    "creator": "admin",
                    "createTime": onece_creat_time.strftime("%Y-%m-%d %H:%M:%S"),
                },
                "SrcName": "文件名",
                "partment": Server_config.Partment,  # 部门
                "honeyPointIP": honeyPointSystemIP,
                'honeyPointNode': "蜜点",  # 蜜点名称
                "honeyPointName": "文件名",  # 蜜点名称
                "trigger_time": onece_trigger_time.strftime("%Y-%m-%d %H:%M:%S"),
                "reportIP": onece_src_ip,  # 攻击者IP
                "attackIP": onece_src_ip,  # 攻击者IP
                'deployService': honeyPointSystemIP,
                "description": onece_filename+"-"+onec_host_ip+"-"+onece_location,  # 告警描述
                "nodeType": "蜜点",
                "honeyType": "文件蜜点",
                "time": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                "honeyNetworkType": "out",  # 蜜点类型: 内/外蜜点
                "sub_device_type": "外蜜点",  # 蜜点类型: 内/外蜜点
                "level": 500,  # 告警等级 100 300 500
                "attackType": "1",  # 攻击类型
            }
        print(info)
        try:
            for index, producer in enumerate(producer_list):
                print(f"Push to:producer{producer}")
                future = producer.send(Server_config.Kafka_file_topic_list[index], value=info)
                count =count+1
        except Exception as e:
            print(e)
            return 1, e
    # 刷新并关闭所有生产者
    for producer in producer_list:
        producer.flush()
        producer.close()
    return 0, count

# 上传假邮件告警数据
def kafka_email_test():
    email_info = {
        "companyId": "单位id",
        'nodeId': "节点id",  # 蜜点系统id
        "honeyPointIP": "蜜点ip",  # 蜜点系统ip
        "honeyPointNode": "蜜点节点",  # 蜜点系统节点id
        "emailService": "邮箱服务器",
        "emailAccount": "邮箱账户",
        "emailTitle": "邮件标题",
        "emailHeader": "邮件头部",
        "emailType": "邮件类型",    # 邮件类型 1：pop3 2：imap
        "emailRiskType": "邮件风险类型",  # 邮件风险类型 1：钓鱼邮件 2：垃圾邮件
        "riskClassification": "邮件风险类型",
        "srcEmail": "发件人",
        "time": get_time_bj().strftime("%Y-%m-%d %H:%M:%S"),
        "countermeasures": "no",
        "nodeType": "蜜点",
        "honeyType": "邮件蜜点"

    }
    # 修改字段数据
    for index, producer in enumerate(producer_list):
        email_info["companyId"] 
        print("推送消息至:", producer)
        try:
            # 发送至第二个producer的Kafka_file_topic
            producer_list[0].send(Server_config.Kafka_email_topic_list[0], value=email_info)

        except Exception as e:
            print(e)
            return 1, e
        return 0, 1

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Kafka Testing Script")
    parser.add_argument('-n', '--num', type=int, default=1, help='推送的测试数据条数')
    parser.add_argument('-r', action='store_true', help='推送真实数据')
    parser.add_argument('-t', action='store_true', help='实时触发时间')
    args = parser.parse_args()
    
    print("[kafka] 正在初始化Kafka连接...")
    for index, Kafka_server in enumerate(Server_config.kafka_server_list): # 初始化配置文件中的kafka连接
        res, info = kafka_init(Kafka_server)
        if res:
            print(f"[Kafka] [{index}] 初始化成功:{Kafka_server}")
        else:
            print(f"[Kafka] [{index}] 初始化失败{Kafka_server},{info}")
            exit(0)
    
    if len(producer_list) == 0:
        print("[kafka] producer列表为空")
        exit(0)
        pass
    if args.t:
        isRealTime = True
    else:
        isRealTime = False
    if args.r:
        from flask_server import create_app
        app = create_app()
        with app.app_context():
            err,info = send_alert_file(None)
        pass
    else:
        num = args.num
        err,info = kafka_file_test(num,isRealTime)
        if err:
            print(f"[Kafka] 推送失败:",info)
            exit(0)
        else:
            print(f"[Kafka] 推送完成")
            
    print(f"[Kafka] 本次成功推送消息数:{info}") 