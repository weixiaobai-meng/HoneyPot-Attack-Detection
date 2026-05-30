# 部署管理模块

## 目录结构

```
deployment/
│
├── auto_deploy.py              # 一键部署脚本 ⭐
├── deploy_manager.py           # 告警收集管理
├── DEPLOY_GUIDE.md             # 详细部署指南
├── README.md                   # 本文件
│
├── config/                     # 配置文件
│   ├── deployment.json         # 部署配置
│   ├── components.json         # 组件配置
│   └── deployed.json           # 部署状态
│
├── scripts/                    # 启动脚本
│   ├── start_systemwire2.bat   # 启动管理端
│   ├── start_alert_server.bat  # 启动告警服务
│   ├── start_ssh_vpn.bat       # 启动SSH蜜罐
│   └── start_agent_go.bat      # 启动探针
│
├── alerts/                     # 收集的告警数据
│   ├── file_alerts.json
│   ├── account_alerts.json
│   ├── parasitic_alerts.json
│   └── audit_alerts.json
│
└── output/                     # 输出目录
    └── collected_alerts.json   # 汇聚后的告警
```

## 快速开始

### 方式一：一键部署（推荐）

```bash
cd deployment
python auto_deploy.py
```

这将自动：
1. 检查环境（Python、Go）
2. 安装Python依赖
3. 初始化数据库
4. 编译Go组件
5. 生成配置文件
6. 创建启动脚本

### 方式二：手动部署

详见 [DEPLOY_GUIDE.md](DEPLOY_GUIDE.md)

## 启动服务

部署完成后，按以下顺序启动服务：

```
1. 启动 systemwire2 (管理端)
   双击 scripts/start_systemwire2.bat
   或: cd ../systemwire2 && python app.py

2. 启动 alert_server (告警服务)
   双击 scripts/start_alert_server.bat

3. 启动 ssh-vpn (SSH蜜罐)
   双击 scripts/start_ssh_vpn.bat

4. 部署 agent-go (探针) 到靶机
   - 复制 agent-go.exe 到靶机
   - 配置 config.ini
   - 运行 agent-go.exe
```

## 收集告警

```bash
# 检查组件状态
python deploy_manager.py check

# 收集告警数据
python deploy_manager.py collect

# 导出到Step1
python deploy_manager.py export
```

## 组件说明

| 组件 | 端口 | 功能 |
|------|------|------|
| systemwire2 | 5001, 50051 | 管理界面 + gRPC服务 |
| alert_server | 8080, 8081 | 告警接收 |
| ssh-vpn | 2222, 1194 | SSH蜜罐 |
| agent-go | - | 探针（部署在靶机） |

## 数据流

```
蜜点触发 → 组件采集 → deployment/alerts/ → deployment/output/ → step1
```

## 常见问题

**Q: agent-go无法连接？**
A: 检查防火墙是否开放50051端口，config.ini中的ServerAddress是否正确。

**Q: 没有收到告警？**
A: 确认蜜点已部署，agent-go正常运行。

**Q: 数据库错误？**
A: 删除 systemwire2/instance/tripwire.db 重新运行 auto_deploy.py。

## 详细文档

- [部署指南](DEPLOY_GUIDE.md) - 完整的部署步骤
- [项目根目录README](../README.md) - 项目整体说明
