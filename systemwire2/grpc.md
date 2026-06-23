1.1. 安装gRPC
```
python -m pip install grpcio
```

1.2. 安装gRPC工具

gRPC工具包括protocol buffer编译器（protoc）和 python代码生成插件，python代码生成插件通过.proto服务定义文件，生成python的grpc服务端和客户端代码。
```
python -m pip install grpcio-tools
```

生成grpc代码

```
python -m grpc_tools.protoc -Iagent-server/proto --python_out=agent-server/proto --grpc_python_out=agent-server/proto agent-server/proto/agent.proto
```