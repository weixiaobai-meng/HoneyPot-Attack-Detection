import logging
import os
import sys
import threading
import time
from flask_server.flask_app import flask_app,init_flask_server
from flask_server.views import repair_honeypot_delivery_chain
from agent_server.server import create_grpc_server,run_grpc_server
from config.config import *

base_dir = os.path.abspath(os.path.dirname(__file__))   # 当前目录
log_dir = os.path.join(base_dir, 'log')                 # 日志目录

if __name__ == '__main__':
    logging.info(f"开始启动服务启动...")
    
    try:
        # 初始化flask server
        init_flask_server()
        create_grpc_server()
        with flask_app.app_context():
            try:
                repair_honeypot_delivery_chain()
                flask_app.logger.info("startup honeypot delivery chain repair executed")
            except Exception as exc:
                flask_app.logger.warning("startup honeypot delivery chain repair failed: %s", exc)
        
        # 启动grpc服务器
        logging.info(f"正在启动gRPC服务器...")
        
        # 启动grpc服务器
        grpc_thread = threading.Thread(
            target=run_grpc_server,
            daemon=True
        )
        grpc_thread.start()
        os.environ["GRPC_INITIALIZED"] = "true"  # 设置环境变量
        logging.info(f"gRPC服务器启动成功,端口 {GRPC_PORT}")
            
        # 启动 Flask 服务
        flask_app.config['TEMPLATES_AUTO_RELOAD'] = True
        flask_app.run(host=FLASK_HOST, port=FLASK_PORT,debug=False)
        
        
    except KeyboardInterrupt:
        logging.info("收到终止信号，正在关闭服务器...")
        sys.exit(0)
    except Exception as e:
        logging.error(f"服务器运行出错: {str(e)}")
        sys.exit(1)
    

