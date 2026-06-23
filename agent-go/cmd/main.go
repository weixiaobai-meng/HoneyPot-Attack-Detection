package main

import (
	"systemwire/agent/internal/agent"
	"systemwire/agent/internal/config"

	"github.com/sirupsen/logrus"
)

// 监控客户端(被监控端程序)
var client *agent.Agent // 客户端
var token string        // 认证token

func main() {
	// 加载配置
	cfg, err := config.NewConfig()
	if err != nil {
		logrus.Fatalf("配置加载出错: %v", err)
	}

	// 检查是否设置token（方式一：配置文件中设置，方式二：编译设置）
	if cfg.Token == "" && token == "" {
		logrus.Fatal("Token 未设置")
	}

	// 创建客户端
	client = agent.NewAgent(cfg, token)

	// 启动Agent
	client.Logger.Info("正在启动Agent...")
	client.Start()
}
