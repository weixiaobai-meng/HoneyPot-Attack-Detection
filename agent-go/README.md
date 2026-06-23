# 服务端监控（被控端）

## 1. 架构

[被控端] -> grpc + tls -> [管理端]

监控模式:Agent

## 2. 项目结构

```
cmd - 入口
config - 配置文件
internal - 核心代码包
pkg - 通用包/工具包
proto - 通信协议文件
ssl - 证书相关文件
tests - 测试用例文件
```

## 3. 项目编译

### 带参数编译命令（非静态编译）

```shell
go build -o agent-go -ldflags "-X 'main.token=xxxxxxxxxx'" ./cmd

// 参数解释：
// -o：编译输出的可执行文件路径及文件名（windows端要以exe为后缀）
// -ldflags：用于将 Token 作为编译参数传递到代码中
// -X ：要编译的变量
// main：表示main.go中的变量
// token：token变量
// .cmd/：入口文件所在路径
```


```shell
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -o agent-go -ldflags "-X 'main.serverAddress=127.0.0.1:50051' -X 'main.token=T3t7oY0NSggpXCCK'" ./cmd
```

### 使用musl C 进行静态编译

```sh
x# 1. 安装工具
sudo apt-get install musl musl-dev musl-tools
# 2.编译
CGO_ENABLED=1 CC=musl-gcc GOOS=linux GOARCH=amd64 go build -ldflags "-linkmode external -extldflags '-static'-X main.token=xxxxxxxxx" -o sysagent ./cmd
```

### gRPC编译
安装protobuf-compiler
```
apt install -y protobuf-compiler
```
安装go的grpc插件
```
# protoc-gen-go插件：用于生成xx.pb.go文件
go install google.golang.org/protobuf/cmd/protoc-gen-go@latest
 
# protoc-gen-go-grpc插件：用于生成xx_grpc.pb.go文件
go install google.golang.org/grpc/cmd/protoc-gen-go-grpc@latest
```

编译命令（在proto目录下执行）
```
protoc --go_out=. --go-grpc_out=. ./agent.proto
```

## 4. 相关配置

#### 4.1audit权限配置

执行命令：

```shell
sudo visudo
```

在打开的权限文件中添加如下行：

```
用户名     ALL=(ALL) NOPASSWD: /usr/sbin/auditctl, /usr/sbin/ausearch
```
