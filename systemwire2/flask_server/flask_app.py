import logging
import sys
import threading
from flask_server.utils.common import service_register, Server_config
from flask_server import create_app
from flask_server.controller.kafka_alert import kafka_init
from logging.handlers import RotatingFileHandler
from config.config import *
import os

flask_app = create_app()  # 创建falsk app
log_dir = "log"                 # 日志目录

# 服务器配置
def server_register():

    flask_app.logger.info("[Nacos] 正在注册服务...")
    if Server_config.Env_mode == "server" and Server_config.Nacos_addr != "":
        flask_app.debug = False
        try:
            res, msg = service_register()  # 注册服务
            if res == 1:
                flask_app.logger.info("[Nacos] 服务注册成功！")
            else:
                flask_app.logger.error(f"[Nacos] 服务注册失败！{msg}")
        except Exception as e:
            flask_app.logger.error("[Nacos] 服务注册失败！")
    elif Server_config.Nacos_addr != "":
        flask_app.logger.info("[Nacos] 未配置nacos，跳过服务注册!")
    
    # 初始化Kafka连接
    flask_app.logger.info("[kafka] 正在初始化Kafka连接...")
    for index, Kafka_server in enumerate(Server_config.kafka_server_list): # 初始化配置文件中的kafka连接
        res, info = kafka_init(Kafka_server)
        if res:
            flask_app.logger.info(f"[Kafka] [{index}] 初始化成功:{Kafka_server}")
        else:
            flask_app.logger.error(f"[Kafka] [{index}] 初始化失败{Kafka_server},{info}")

# 配置flask日志记录器
def setup_flask_logger():
    # 清除已有的处理器，避免重复日志输出
    if flask_app.logger.hasHandlers():
        flask_app.logger.handlers.clear()
    
    # 设置日志文件目录
    if not os.path.exists(log_dir): 
        os.makedirs(log_dir)
    
    formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')

    # 控制台日志配置
    console_handler = logging.StreamHandler()
    if flask_app.debug or Server_config.Env_mode == "debug":
        console_handler.setLevel(logging.DEBUG)
    else:
        console_handler.setLevel(logging.INFO)
    console_handler.setFormatter(formatter)

    # 文件日志配置
    log_file_path = os.path.join(log_dir, 'flask.log')
    file_handler = RotatingFileHandler(log_file_path, maxBytes=10*1024*1024, backupCount=3)  # 10MB * 3 轮转
    file_handler.setLevel(logging.DEBUG)
    file_handler.setFormatter(formatter)

    # 添加处理器
    flask_app.logger.addHandler(console_handler)
    flask_app.logger.addHandler(file_handler)

    # 设置日志级别
    flask_app.logger.setLevel(logging.INFO)

    # 防止子 Logger 冒泡
    flask_app.logger.propagate = False

def init_flask_server():
    # 初始化日志
    setup_flask_logger()
    
    if Server_config.Env_mode == "debug" or Server_config.Env_mode == "alone":
        flask_app.debug = True
        flask_app.logger.info(f"[Nacos] 当前为{Server_config.Env_mode}模式，跳过服务注册！")
        flask_app.logger.info(f"[Kafka] 当前为{Server_config.Env_mode}模式，跳过Kafka初始化！")
    else:
        # 系统蜜点服务初始化(nacos)
        server_register()
        


if __name__ == '__main__':
    # 配置flask服务器
    host = "0.0.0.0"
    flask_port = 5001
    grpc_port = 50051
    
    logging.info(f"开始启动服务启动...")
    
    try:
        init_flask_server()
        flask_app.run(host=host, port=flask_port)
        
    except KeyboardInterrupt:
        logging.info("收到终止信号，正在关闭服务器...")
        sys.exit(0)
    except Exception as e:
        logging.error(f"服务器运行出错: {str(e)}")
        sys.exit(1)
    

