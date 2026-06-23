//go:build windows
// +build windows

package monitor

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"os"
	"sync"
	"systemwire/agent/internal/config"
	"systemwire/agent/internal/models"
	pb "systemwire/agent/proto"
	"time"

	"github.com/fsnotify/fsnotify"
	"github.com/google/uuid"
	"github.com/sirupsen/logrus"
)

var monitorListFile = "config/paths.list"

type FsnotifyMonitor struct {
	pb_client   pb.AgentServiceClient
	logger      *logrus.Logger
	watcher     *fsnotify.Watcher
	paths       map[string]bool
	pathMutex   sync.Mutex
	Running     bool
	evenLogFile string
	errLogFile  string
}

// 创建新的 FsnotifyMonitor 实例
func NewInotifyMonitor(client pb.AgentServiceClient) *FsnotifyMonitor {
	// 初始化 fsnotify
	watcher, err := fsnotify.NewWatcher()
	if err != nil {
		logrus.Fatalf("创建监控出错: %v", err)
		return nil
	}

	logger_obj := config.NewLogger(logrus.DebugLevel, "log/monitor_fsnotify.log")
	return &FsnotifyMonitor{
		pb_client:   client,
		logger:      logger_obj,
		watcher:     watcher,
		paths:       make(map[string]bool),
		evenLogFile: "log/file_event_fsnotify.log",
		errLogFile:  "log/file_err_fsnotify.log",
	}
}

// 检查路径是否存在
func pathExists(path string) (bool, error) {
	info, err := os.Stat(path)
	if os.IsNotExist(err) {
		return false, nil
	}
	return info != nil, err
}

// 启动监控
func (m *FsnotifyMonitor) Start(ctx context.Context) error {
	if m.Running {
		return nil
	}
	m.Running = true

	// 从文件读取监控路径
	paths, err := config.LoadMonitorPath(monitorListFile)
	if err != nil {
		return err
	}

	// 设置监控路径
	err = m.AddPaths(paths)
	if err != nil {
		return err
	}

	// 获取监控路径，检查是否正确添加
	loadedPaths := m.GetPath()
	m.logger.Info("当前监控路径：", loadedPaths)

	// 启动事件处理goroutine
	go m.handleEvents(ctx)

	return nil
}

// 处理 fsnotify 事件
func (m *FsnotifyMonitor) handleEvents(ctx context.Context) {
	for {
		select {
		case <-ctx.Done():
			return
		case event, ok := <-m.watcher.Events:
			if !ok {
				return
			}

			var eventType int
			switch {
			case event.Op&fsnotify.Create == fsnotify.Create:
				eventType = models.EventTypeCreate
			case event.Op&fsnotify.Write == fsnotify.Write:
				eventType = models.EventTypeModify
			case event.Op&fsnotify.Remove == fsnotify.Remove:
				eventType = models.EventTypeDelete
			case event.Op&fsnotify.Rename == fsnotify.Rename:
				eventType = models.EventTypeDelete
			case event.Op&fsnotify.Chmod == fsnotify.Chmod:
				eventType = models.EventTypeModify
			default:
				fmt.Println("事件操作：", event)
				continue
			}

			monitorEvent := &models.MonitorEvent{
				Id:        uuid.New().String(),
				EventType: eventType,
				EventTime: time.Now(),
				Path:      event.Name,
				Data:      "",
			}

			if err := m.HandleEvent(ctx, []*models.MonitorEvent{monitorEvent}); err != nil {
				m.logger.Errorf("事件处理出错: %v", err)
			}

		case err, ok := <-m.watcher.Errors:
			if !ok {
				return
			}
			m.logger.Errorf("监控错误: %v", err)
			m.saveErrorToFile(err.Error())
		}
	}
}

// 停止监控
func (m *FsnotifyMonitor) Stop() error {
	m.pathMutex.Lock()
	defer m.pathMutex.Unlock()

	if !m.Running {
		return errors.New("monitor 未启动")
	}

	err := m.watcher.Close()
	if err != nil {
		return err
	}

	m.Running = false
	return nil
}

// 重启监控
func (m *FsnotifyMonitor) Restart(ctx context.Context) error {
	err := m.Stop()
	if err != nil {
		return err
	}

	// 重新创建 watcher
	watcher, err := fsnotify.NewWatcher()
	if err != nil {
		return err
	}
	m.watcher = watcher

	return m.Start(ctx)
}

// 添加监控路径
func (m *FsnotifyMonitor) AddPaths(paths []string) error {
	m.pathMutex.Lock()
	defer m.pathMutex.Unlock()

	for _, path := range paths {
		exists, err := pathExists(path)
		if !exists {
			log.Printf("路径不存在: %s", path)
			return errors.New("路径不存在")
		}
		if err != nil {
			log.Printf("检查路径时发生错误: %v", err)
			return err
		}

		err = m.watcher.Add(path)
		if err != nil {
			log.Printf("添加监控路径失败: %s, 错误: %v", path, err)
			return err
		}

		m.paths[path] = true
		log.Println("添加监控路径成功", path)
	}
	return nil
}

// 删除监控路径
func (m *FsnotifyMonitor) RemovePath(paths []string) error {
	m.pathMutex.Lock()
	defer m.pathMutex.Unlock()
	for _, path := range paths {
		if !m.paths[path] {
			return errors.New("path 不存在")
		}

		err := m.watcher.Remove(path)
		if err != nil {
			return err
		}

		delete(m.paths, path)
	}

	return nil
}

// 获取监控路径
func (m *FsnotifyMonitor) GetPath() []string {
	m.pathMutex.Lock()
	defer m.pathMutex.Unlock()

	var paths []string
	for path := range m.paths {
		paths = append(paths, path)
	}
	return paths
}

// 处理事件
func (m *FsnotifyMonitor) HandleEvent(ctx context.Context, events []*models.MonitorEvent) error {
	select {
	case <-ctx.Done():
		m.logger.Info("正在停止处理事件...")
		return ctx.Err()
	default:
		for _, event := range events {
			eventMessage := event.GetEventPb()
			m.logger.Info(eventMessage)
			if err := m.saveEventToFile(event); err != nil {
				return err
			}

			if m.pb_client != nil {
				fb, err := m.pb_client.ReportMonitorEvent(context.Background(), eventMessage)
				if err != nil {
					m.logger.Errorf("告警推送出错,%v", err)
					m.saveErrorToFile(err.Error())
				}
				log.Println("上报反馈:", fb)
				time.Sleep(time.Second * 1)
			}
		}
	}
	return nil
}

// 将事件写入到 JSON 文件中
func (m *FsnotifyMonitor) saveEventToFile(event *models.MonitorEvent) error {
	file, err := os.OpenFile(m.evenLogFile, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		m.logger.Error("[Monitor] 无法打开事件日志文件: ", err)
		return err
	}
	defer file.Close()

	encoder := json.NewEncoder(file)
	if err := encoder.Encode(event); err != nil {
		m.logger.Error("事件写入文件时出错: ", err)
		return err
	}
	return nil
}

func (m *FsnotifyMonitor) saveErrorToFile(info string) error {
	file, err := os.OpenFile(m.errLogFile, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		return err
	}
	defer file.Close()

	_, err = file.WriteString(info + "\n")
	return err
}

func (m *FsnotifyMonitor) SetRPCClient(client pb.AgentServiceClient) {
	m.pb_client = client
}

// 返回监控运行状态
func (m *FsnotifyMonitor) GetMonitorState() bool {
	return m.Running
}
