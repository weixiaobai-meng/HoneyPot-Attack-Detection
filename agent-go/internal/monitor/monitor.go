package monitor

import (
	"context"
	"systemwire/agent/internal/models"
	pb "systemwire/agent/proto"
)

// 监控接口
type Monitor interface {
	// 启动监控
	Start(ctx context.Context) error
	// 停止监控
	Stop() error
	// 重启监控
	Restart(ctx context.Context) error
	// 添加监控路径
	AddPaths(paths []string) error
	// 删除监控路径
	RemovePath(paths []string) error
	// 获取监控路径
	GetPath() []string
	// 处理事件
	HandleEvent(ctx context.Context, events []*models.MonitorEvent) error
	SetRPCClient(client pb.AgentServiceClient)
}
