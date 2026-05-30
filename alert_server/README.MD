# 蜜点告警器
## 1. 项目介绍
此项目为四蜜系统-系统蜜点的一部分，用于接收文件告警、接收寄生蜜点告警等

## 2. 代码结构
```
alert_server/
│
├── cmd/
│   └── main.go         # 项目入口
│
├── data/       # 数据库
│
├── dist/       # 项目编译后的可执行文件
│
├── config/     # 配置
│   ├── config.ini      # 配置文件
│   ├── ip_block.list   # 黑名单IP
│   └── ip_white.list   # 白名单IP
│
├── pkg/        # 通用功能函数代码
│   ├── common.go       # 通用功能函数
│   ├── config.go       # 配置文件相关函数
│   ├── db.go           # 数据库相关函数
│   ├── filter.go       # 黑白名单过虑器相关函数
│   ├── logger.go       # 日志记录器相关函数
│   └── mail.go         # 发送邮件相关函数
│
├── internal/   # 后端核心架构代码
│   ├── handler/        # 处理器/controller 代码
│   ├── middlerware/    # 中间件 代码
│   ├── models/         # 数据库 相关代码
│   └── routes/         # 路由/接口绑定 相关代码
│
└── log/        # 日志
│
└── ssl/        # 证书
│
└── templates/  # 网页模板
```

## 3. 部署
### 3.1 程序编译
将项目代码编译成一个可执行文件,在项目根目录下执行如下命令：

```
go build -o dist/server-x.x.x cmd/main.go
```

解释：

-o 编译后的路径

cmd/main.go 程序入口

## 4. TODO
<ul>
  <li><input type="checkbox"> 整合寄生蜜点告警接收服务器</li>
</ul>
