# agent服务端:用于管理agent列表
import time
import logging
import threading
import grpc
from  agent_server.proto import agent_pb2 as pb2
from  agent_server.proto import agent_pb2_grpc as pb2_grpc
from concurrent import futures
from .grpc_auth import AuthInterceptor
from .agent_service_servicer import AgentServiceServicer
from flask_server.models import ClientInfo, SessionFactory
from .agent import *
from .logger import new_logger
from config.config import *

class Server():
    # 单例模式
    _instance_lock = threading.Lock()
    agent_list_lock = threading.Lock()  # 用于保护 agent_list 的线程安全
    _secret_to_id = {}
    agent_list = {}
    commond_queue = {}
    logger = None
    def __new__(cls, *args, **kwargs):
        if not hasattr(Server,"_instance"):
            with Server._instance_lock:
                if not hasattr(Server,"_instance"):
                    Server._instance = object.__new__(cls)
        return Server._instance
    
    def __init__(self):
        if not hasattr(self, '_initialized'):
            # 初始化Server
            self.logger = new_logger("Agent",logging.DEBUG)     # 实例化日志
            self.logger.info("正在初始化 探针服务器...")
            self.grpc_server = self.create_server_whit_auth()   # 实例化grpc server
            pb2_grpc.add_AgentServiceServicer_to_server(AgentServiceServicer(self._instance),self.grpc_server)  #实现了 RPC 接口，等待客户端调用
            
            # 加载agent list
            agent_count = self.load_agent()
            self.logger.info(f"Agent加载完毕，总数：{agent_count}")
            
            self._initialized = True                    # 标记已经初始化完成
        
    def create_server_whit_auth(self):
        auth_interceptor = AuthInterceptor()
        auth_interceptor.set_server(self)
        grpc_server = grpc.server(futures.ThreadPoolExecutor(max_workers=10), interceptors=(auth_interceptor,))
        # 启用TLS认证
        if TLS_ENABLE:
            self.logger.info("TLS认证：开启")
            # 单向认证
            if AUTH_TYPE == "single":
                self.logger.info(f"认证方式：单向认证")
                # 加载证书和密钥
                with open(SERVER_KEY_PATH,'rb') as f:
                    server_key = f.read()  # 读取服务端私钥
                with open(SERVER_CERT_PATH,'rb') as f:
                    server_cert = f.read() # 读取服务端证书
                creds = grpc.ssl_server_credentials(((server_key,server_cert),)) # 创建grpc证书实例
                grpc_server.add_secure_port('[::]:'+GRPC_PORT,creds) # 启动安全连接监听
            # 双向认证
            elif AUTH_TYPE == "double":
                self.logger.info("认证方式：双向认证")
                # 加载证书和密钥
                with open(SERVER_KEY_PATH,'rb') as f:
                    server_key = f.read()  # 读取服务端私钥
                    f.close
                with open(SERVER_CERT_PATH,'rb') as f:
                    server_cert = f.read() # 读取服务端证书
                    f.close
                with open(CA_CERT_PATH, 'rb') as f:
                    ca_cert = f.read()
                    f.close
                creds = grpc.ssl_server_credentials(
                    [(server_key,server_cert)],
                    root_certificates=ca_cert,
                    require_client_auth=True
                )
                
                grpc_server.add_secure_port('[::]:'+GRPC_PORT,creds)
            else:
                self.logger.error("认证方式不存在: ",AUTH_TYPE)
                return None
        else:
            self.logger.info(f"TLS认证：关闭")
            grpc_server.add_insecure_port('[::]:'+GRPC_PORT) 
        return grpc_server

    # 加载agent列表
    def load_agent(self)->int:
        """加载agent列表
        Return: 返回加载的agent数量
        """

        self.agent_list = {}
        self._secret_to_id = {}
        self.commond_queue = {}

        session = SessionFactory()
        try:
            agents = session.query(ClientInfo).all()
            changed = False
            for each in agents:
                if each.status != "offline":
                    each.status = "offline"
                    changed = True

                agent_json = each.to_json()
                agent = Agent(agent_json)
                agent.status = "offline"
                self.agent_list[agent_json["client_id"]] = agent
                self._secret_to_id[agent_json["token"]] = agent_json["client_id"]

            if changed:
                session.commit()
            return len(agents)
        except Exception as e:
            session.rollback()
            self.logger.error(f"加载Agent列表失败: {e}")
            return 0
        finally:
            session.close()
    
    # 心跳监测
    def start_alive_detection(self, stop_event, interval=60):
        while not stop_event.is_set():
            # print("开始检测 Agent 的连接状态...")

            for _,agent in self.agent_list.items():
                if agent.status == "online":
                    try:
                        # 下发任务（心跳包）
                        # with self.agent_list_lock:  # 加锁以确保线程安全地访问 agent_list
                        beat_cmd = pb2.Cmd(id=1, type=CmdBeat, data="")
                        agent.command_queue.put(beat_cmd)  # 使用同步队列
                    except Exception as e:
                        print(f"Failed to send heartbeat to agent {agent.uid}: {e}")
                        agent.status = "offline"  # 如果无法发送心跳包，标记为掉线

            # 等待下一个心跳间隔
            time.sleep(interval)

    

