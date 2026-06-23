// 文件路径: tests/sysdig_monitor_test.go
package tests

import (
	"context"
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"
	"systemwire/agent/internal/monitor"
	"testing"
	"time"
)

// TestSysdigMonitor 测试 SysdigMonitor 的基本功能
func TestSysdigMonitor(t *testing.T) {
	// 捕获 SIGINT 和 SIGTERM 信号，确保主进程退出时停止所有子进程
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)

	// 创建 SysdigMonitor 实例
	m := monitor.NewSysdigMonitor(nil)

	dir1 := "/home/cly/test"
	dir2 := "/var/www/html/login/"
	var paths []string
	paths = append(paths, dir1)
	paths = append(paths, dir2)
	// 添加监控路径
	if err := m.AddPaths(paths); err != nil {
		t.Errorf("添加监控路径失败: %v", err)
	}
	// 获取监控路径，检查是否正确添加
	paths = m.GetPath()
	if len(paths) != 1 || paths[0] != dir1 {
		t.Errorf("获取监控路径失败, 期望: %s, 实际: %v", dir1, paths)
	}

	// 启动监控
	go func() {
		if err := m.Start(ctx); err != nil {
			fmt.Printf("启动监控失败: %v", err)
		}
	}()

	// 等待信号
	sig := <-sigChan
	m.Stop()
	cancel()
	log.Printf("收到信号: %s, 正在停止所有监控器...", sig)
	time.Sleep(time.Second * 3)
}

// TestHandleEvent 测试事件处理逻辑
func TestHandleEvent(t *testing.T) {
	m := monitor.NewSysdigMonitor(nil)

	// 模拟一个 sysdig 输出的事件行
	eventLine := "12:34:56.789 user process parentprocess evt.type fd.args fd.name cmdline cwd info"

	// 调用 HandleEvent 方法处理事件
	event, err := m.ParseEvent(eventLine)
	if err != nil {
		t.Errorf("事件处理失败: %v", err)
	}
	fmt.Println(event)
}

// // TestConcurrentOperations 测试并发操作安全性
// func TestConcurrentOperations(t *testing.T) {
// 	m := monitor.NewSysdigMonitor()

// 	// 并发操作监控器
// 	for i := 0; i < 10; i++ {
// 		go func(i int) {
// 			tempPath := filepath.Join("/tmp", "testpath", string(i))
// 			if err := m.AddPath(tempPath); err != nil {
// 				log.Printf("添加路径失败: %v", err)
// 			}
// 			if err := m.Start(); err != nil {
// 				log.Printf("启动监控失败: %v", err)
// 			}
// 			time.Sleep(500 * time.Millisecond)
// 			if err := m.Stop(); err != nil {
// 				log.Printf("停止监控失败: %v", err)
// 			}
// 			if err := m.RemovePath(tempPath); err != nil {
// 				log.Printf("删除路径失败: %v", err)
// 			}
// 		}(i)
// 	}

// 	// 等待并发操作完成
// 	time.Sleep(3 * time.Second)
// }
