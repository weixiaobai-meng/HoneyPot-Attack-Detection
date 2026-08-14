# 蜜点系统部署指南

## 系统架构

```
┌─────────────────────────────────────────────────────────────────┐
│                        管理端 (你的电脑)                         │
│  ┌────────────────────────────────────────────────────────────┐│
│  │  systemwire2 (Flask + gRPC)                                ││
│  │  - Web管理界面: http://localhost:5001                       ││
│  │  - gRPC服务: 0.0.0.0:50051                                 ││
│  └────────────────────────────────────────────────────────────┘│
│                              │                                  │
│                              │ gRPC + TLS                       │
│                              ▼                                  │
│  ┌────────────────────────────────────────────────────────────┐│
│  │  靶机 (被监控的服务器)                                      ││
│  │  - agent-go: 监控文件操作、部署蜜点                         ││
│  └────────────────────────────────────────────────────────────┘│
│                                                                  │
│  ┌──────────────────────┐  ┌──────────────────────┐            │
│  │  alert_server        │  │  ssh-vpn             │            │
│  │  文件蜜点告警接收    │  │  SSH蜜罐             │            │
│  └──────────────────────┘  └──────────────────────┘            │
└─────────────────────────────────────────────────────────────────┘
```

## 部署步骤

### 1. 启动 systemwire2 (管理端)

```bash
cd systemwire2

# 安装依赖
pip install -r requirements.txt

# 创建配置文件
cp config/config.py.example config/config.py
# 编辑 config/config.py 修改配置

# 启动服务
python app.py
```

访问 http://localhost:5001 进入管理界面。

### 2. 启动 alert_server (文件告警接收)

```bash
cd alert_server

# 创建配置文件
cp config/config.ini.example config/config.ini
# 编辑 config/config.ini 修改配置

# 编译运行
go build -o alert_server cmd/main.go
./alert_server
```

### 3. 编译 agent-go (靶机代理)

```bash
cd agent-go

# 编译
go build -o agent-go ./cmd

# 或者交叉编译Linux版本
GOOS=linux GOARCH=amd64 go build -o agent-go ./cmd
```

### 4. 部署 agent-go 到靶机

```bash
# 复制到靶机
scp agent-go user@target:/opt/agent/

# 在靶机上配置
ssh user@target
cd /opt/agent
cp config/config.ini.example config/config.ini
# 编辑 config.ini，配置管理端地址和Token

# 启动
./agent-go
```

### 5. 启动 ssh-vpn (SSH蜜罐)

```bash
cd ssh-vpn

# 编译
go build -o ssh-auth-logger

# 启动
./ssh-auth-logger
```

## 蜜点部署功能

### 文件蜜点部署

1. 在管理界面创建文件蜜点
2. 进入 "蜜点部署 -> 文件蜜点"
3. 选择探针和文件
4. 填写部署路径
5. 点击"开始部署"

### 寄生蜜点部署

1. 进入 "蜜点部署 -> 寄生蜜点"
2. 选择探针
3. 填写目标网站目录
4. 配置JS脚本（URL或内容）
5. 点击"开始部署"

### 账户蜜点部署

1. 进入 "探针管理 -> 探针列表"
2. 选择探针，点击"部署账户蜜点"
3. 填写账户信息（用户名、密码等）

## 告警收集

### 统一告警中心

访问 "告警中心" 查看所有类型的告警：
- 文件告警：文件蜜点被触发
- 寄生告警：网页被爬虫/机器人访问
- 审计告警：文件系统操作监控

### 导出告警数据

1. 在告警中心点击"导出"按钮
2. 或访问API: `GET /api/alerts/unified?hours=24`

### 告警数据格式

```json
{
    "alert_id": "audit_123",
    "alert_type": "audit",
    "timestamp": "2024-01-15T10:30:00",
    "attacker_ip": "192.168.1.100",
    "target_path": "/home/user/password.txt",
    "action": "openat",
    "details": {
        "proctitle": "cat /home/user/password.txt",
        "pid": "12345"
    }
}
```

## 后续步骤（正式实验）

收集到真实告警后，先生成独立场景数据和盲标注模板：

```powershell
python thesis_experiment_pipeline.py --run-name scenario_001 --hours 24
```

完成双人标注并建立训练、验证、测试场景清单后，再运行数据校验和正式基准：

```powershell
python -m experiments.validate_dataset --manifest experiments/data/manifest.json
python -m experiments.run_benchmark --manifest experiments/data/manifest.json --output-dir experiments/results/benchmark_v1
```

不得使用旧版合成告警、单图增强或自动生成的弱标签作为论文实验数据。完整步骤见
`experiments/EXPERIMENT_EXECUTION_GUIDE.md`。

## 常见问题

### 1. 探针无法连接

检查：
- 防火墙是否开放50051端口
- config.ini中的ServerAddress是否正确
- Token是否匹配

### 2. 文件蜜点部署失败

检查：
- 探针是否在线
- 目标路径是否存在且有写入权限
- 文件蜜点是否已创建

### 3. 寄生蜜点无告警

检查：
- JS脚本是否正确加载
- 目标网页是否被访问
- 告警日志是否有记录
