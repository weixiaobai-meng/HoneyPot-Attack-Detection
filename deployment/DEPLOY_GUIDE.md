# 蜜点系统部署指南

## 部署架构

```
┌─────────────────────────────────────────────────────────────────┐
│                     管理服务器 (你的电脑)                         │
│                                                                 │
│   ┌─────────────────┐    ┌─────────────────┐                   │
│   │   systemwire2   │    │  alert_server   │                   │
│   │   (管理端)      │    │  (告警服务)     │                   │
│   │   :5001 Web     │    │  :8080 HTTP     │                   │
│   │   :50051 gRPC   │    │  :8081 Admin    │                   │
│   └─────────────────┘    └─────────────────┘                   │
│                                                                 │
└─────────────────────────────────────────────────────────────────┘
            │ gRPC                        │ HTTP
            ▼                             ▼
┌─────────────────────────────────────────────────────────────────┐
│                       靶机/服务器                                │
│                                                                 │
│   ┌─────────────────┐    ┌─────────────────┐                   │
│   │    agent-go     │    │    ssh-vpn      │                   │
│   │   (探针)        │    │   (SSH蜜罐)     │                   │
│   │   部署蜜点      │    │   :22 SSH      │                   │
│   │   采集日志      │    │   :1194 VPN     │                   │
│   └─────────────────┘    └─────────────────┘                   │
│                                                                 │
│   ┌─────────────────┐    ┌─────────────────┐                   │
│   │   文件蜜点      │    │   寄生蜜点      │                   │
│   │  /home/user/... │    │  /var/www/...   │                   │
│   └─────────────────┘    └─────────────────┘                   │
│                                                                 │
└─────────────────────────────────────────────────────────────────┘
```

## 部署步骤

### 第一步：安装依赖

#### 1.1 Python依赖 (systemwire2)

```bash
cd systemwire2
pip install -r requirements.txt
```

#### 1.2 Go依赖 (alert_server, agent-go, ssh-vpn)

```bash
# alert_server
cd alert_server
go mod download

# agent-go
cd agent-go
go mod download

# ssh-vpn
cd ssh-vpn
go mod download
```

### 第二步：配置文件

#### 2.1 systemwire2配置

编辑 `systemwire2/config/config.py`:

```python
# Flask配置
FLASK_HOST = "0.0.0.0"
FLASK_PORT = 5001

# gRPC配置
GRPC_PORT = "50051"
TLS_ENABLE = True

# 数据库
DB_TYPE = "sqlite"
DB_FILE_NAME = "tripwire.db"
```

#### 2.2 alert_server配置

编辑 `alert_server/config/config.ini`:

```ini
[server]
public_ip = 你的公网IP
public_port = 8080
local_port = 8081
api-key = 你的API密钥

[alert]
mode = 1
admin_email = your@email.com
```

#### 2.3 agent-go配置

编辑 `agent-go/config/config.ini`:

```ini
[AGENT]
AgentMode = online
ServerAddress = 管理服务器IP:50051
Token = 你的Token
ReportInterval = 5
MonitorType = audit

[TLS]
Enable = true
AuthType = 2
CACertPath = ssl/ca.crt
ClientCertPath = ssl/client.pem
ClientKeyPath = ssl/client.key
```

### 第三步：生成SSL证书

```bash
# 生成CA证书
openssl genrsa -out ca.key 2048
openssl req -new -x509 -days 365 -key ca.key -out ca.crt

# 生成服务端证书
openssl genrsa -out server.key 2048
openssl req -new -key server.key -out server.csr
openssl x509 -req -days 365 -in server.csr -CA ca.crt -CAkey ca.key -out server.pem

# 生成客户端证书
openssl genrsa -out client.key 2048
openssl req -new -key client.key -out client.csr
openssl x509 -req -days 365 -in client.csr -CA ca.crt -CAkey ca.key -out client.pem
```

将证书复制到对应目录:
- 服务端: `systemwire2/agent_server/ssl/`
- 客户端: `agent-go/ssl/`

### 第四步：启动服务

#### 4.1 启动管理端 (systemwire2)

```bash
cd systemwire2
python app.py
```

启动后访问: http://localhost:5001

#### 4.2 启动告警服务 (alert_server)

```bash
cd alert_server
go build -o alert_server cmd/main.go
./alert_server
```

#### 4.3 部署探针 (agent-go)

```bash
# 编译
cd agent-go
go build -o agent-go ./cmd

# 复制到靶机
scp agent-go user@靶机:/opt/agent/

# 在靶机上配置并启动
ssh user@靶机
cd /opt/agent
./agent-go
```

#### 4.4 启动SSH蜜罐 (ssh-vpn)

```bash
cd ssh-vpn
go build -o ssh-auth-logger
./ssh-auth-logger
```

### 第五步：部署蜜点

#### 5.1 通过Web界面部署文件蜜点

1. 登录 http://localhost:5001
2. 进入 "蜜点部署 -> 文件蜜点"
3. 选择探针和文件
4. 填写部署路径
5. 点击"部署"

#### 5.2 通过Web界面部署账户蜜点

1. 进入 "蜜点部署 -> 账户蜜点"
2. 选择探针
3. 填写凭证信息
4. 点击"部署"

#### 5.3 通过Web界面部署寄生蜜点

1. 进入 "蜜点部署 -> 寄生蜜点"
2. 选择探针
3. 填写目标网站目录
4. 配置JS脚本
5. 点击"部署"

### 第六步：收集告警

```bash
# 检查组件
python deployment/deploy_manager.py check

# 收集告警
python deployment/deploy_manager.py collect

# 导出到Step1
python deployment/deploy_manager.py export
```

## 常见问题

### Q1: agent-go无法连接到systemwire2

检查:
1. 防火墙是否开放50051端口
2. config.ini中的ServerAddress是否正确
3. SSL证书是否正确配置

### Q2: 文件蜜点部署失败

检查:
1. 探针是否在线
2. 目标路径是否有写入权限
3. 文件蜜点是否已创建

### Q3: 没有收到告警

检查:
1. 蜜点是否正确部署
2. alert_server是否正常运行
3. agent-go是否正常运行

## 端口列表

| 服务 | 端口 | 说明 |
|------|------|------|
| systemwire2 Web | 5001 | 管理界面 |
| systemwire2 gRPC | 50051 | 探针通信 |
| alert_server HTTP | 8080 | 告警接收 |
| alert_server Admin | 8081 | 管理接口 |
| ssh-vpn SSH | 22 | SSH蜜罐 |
| ssh-vpn VPN | 1194 | VPN蜜罐 |
