import grpc._server
from grpc_interceptor import ServerInterceptor
from concurrent import futures
import os
import grpc

# 实例化服务端拦截器接口
class AuthInterceptor(ServerInterceptor):
    def __init__(self):
        self.server = None  # 绑定的 grpc_server

    def set_server(self,server):
        """
        绑定服务器对象
        """
        self.server = server
        
    def intercept(self, method, request, context, method_name):
        """
        gRPC 拦截器入口，拦截服务请求进行认证
        """
        # 获取请求的元数据，提取token
        metadata = dict(context.invocation_metadata())
        agent_id,error_message= self._auth_token(context,metadata,"authentication")
        
        # 验证失败
        if not agent_id:
            self.server.logger.info(f"认证失败: {context.peer()} - {error_message}")
            context.abort(grpc.StatusCode.UNAUTHENTICATED, "Invalid or mismatched token")
        
        # 认证成功，在trailing metadata中传递agent_id以便后续使用
        context.set_trailing_metadata((('agent_id', agent_id),))    # 传递client_id/agent_id
        
        return method(request,context)
    
    # 验证逻辑代码
    def _auth_token(self, context, metadata, token_field_name):
        """
        验证逻辑：验证 token 和 IP 地址匹配
        Args:
            context: gRPC 请求上下文
            metadata: 请求元数据
            auth_field: 要验证的字段（如 "authentication"）
        
        Returns:
            (agent_id, error_message): 返回 agent_id（成功时）或失败原因（失败时）
        """
        # 提取 token
        token = metadata.get(token_field_name)
        if not token:
            return None, "Token 缺失"

        # TODO:加强认证逻辑
        
        # 验证 token 是否存在
        agent_id = self.server._secret_to_id.get(token)
        if not agent_id:
            return None, "Token 不匹配"

        # 验证 IP 地址
        remote_ip = self._extract_remote_ip(context)
        if not remote_ip:
            return None, "无法提取客户端 IP"
        
        expected_ip = self.server.agent_list[agent_id].ip
        if expected_ip!='' and remote_ip != expected_ip:
            # 开启了ip限制 && 当前客户端ip与设定的ip不匹配
            return None, f"IP 地址不匹配: {remote_ip} != {expected_ip}"

        return agent_id, None
    
    
    def _extract_remote_ip(self, context):
        """
        提取客户端 IP 地址
        Args:
            context: gRPC 请求上下文
        
        Returns:
            客户端 IP 地址 (str)，如果解析失败返回 None
        """
        try:
            # gRPC context.peer() 格式为 "ipv4:<ip>:<port>"
            peer = context.peer()
            if peer.startswith("ipv4:") or peer.startswith("ipv6:"):
                return peer.split(":")[1]
        except Exception as e:
            if self.server and hasattr(self.server, 'logger'):
                self.server.logger.error(f"提取客户端 IP 时出错: {e}")
        return None