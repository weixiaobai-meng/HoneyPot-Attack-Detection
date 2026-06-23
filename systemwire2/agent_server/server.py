import threading
from config.config import *
from .core.server import Server

server = None
def create_grpc_server():
    global server
    if server is None:
        server = Server()
    return server

def get_grpc_server():
    if server is None:
        raise RuntimeError("Server is not initialized. Call create_grpc_server first!")
    return server

# 启动grpc服务端
def run_grpc_server():
    # 启动服务
    server.logger.info("Agent 服务器启动中...")
    server.grpc_server.start()
    
    # 线程控制
    stop_event = threading.Event()
    # 启动心跳检测的线程
    heartbeat_thread = threading.Thread(target=server.start_alive_detection, args=(stop_event,10,), daemon=True)
    heartbeat_thread.start()
    
    server.logger.info(f"gRPC服务端已启用，端口{GRPC_PORT}")
    try:
        server.logger.info("gRPC服务端运行中...")
        server.grpc_server.wait_for_termination()
    except KeyboardInterrupt:   # 程序被打断
        server.logger.info("正在停止gRPC服务端...")
        stop_event.set()
        server.grpc_server.stop(grace=2)    # 五秒之后停止服务
        server.logger.info("gRPC服务端已停止")
        
if __name__ == "__main__":
    run_grpc_server()