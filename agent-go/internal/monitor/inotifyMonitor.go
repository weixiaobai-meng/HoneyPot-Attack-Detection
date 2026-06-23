//go:build linux
// +build linux

package monitor

import (
	"context"
	"encoding/json"
	"errors"
	"log"
	"os"
	"sync"
	"syscall"
	"systemwire/agent/internal/models"
	"time"
	"unsafe"

	"systemwire/agent/internal/config"
	pb "systemwire/agent/proto"

	"github.com/google/uuid"
	"github.com/sirupsen/logrus"
)

type InotifyMonitor struct {
	pb_client   pb.AgentServiceClient // agent客户端
	logger      *logrus.Logger        // 日志记录器
	paths       map[string]int        // 监控路径和对应的watch descriptor
	wdToPaths   map[int]string        // 文件描述符到path映射
	fd          int                   // inotify 文件描述符
	pathMutex   sync.Mutex            // 用于保护并发访问
	Running     bool                  // 监控是否正在运行
	event_type  uint32                // 监控事件类型
	evenLogFile string                // 文件监控记录路径
	errLogFile  string                // 报错日志
}

// 创建一个新的 InotifyMonitor 实例
func NewInotifyMonitor(client pb.AgentServiceClient) *InotifyMonitor {
	// 初始化 inotify 文件描述符
	var err error
	fd, err := syscall.InotifyInit()
	if err != nil {
		log.Fatal("Monitor初始化失败")
		return nil
	}
	logger_obj := config.NewLogger(logrus.DebugLevel, "log/monitor_inotify.log")
	return &InotifyMonitor{
		pb_client: client, // 绑定客户端
		logger:    logger_obj,
		paths:     make(map[string]int), // 初始化监控路径映射
		wdToPaths: make(map[int]string), // 初始化wd到路径的映射
		//所有监控事件
		event_type:  syscall.IN_OPEN | syscall.IN_CREATE | syscall.IN_DELETE | syscall.IN_MODIFY | syscall.IN_ATTRIB | syscall.IN_MOVE,
		fd:          fd,
		evenLogFile: "log/file_event_inotify.log", // 文件监控事件
		errLogFile:  "log/file_err_inotify.log",   // 文件监控事件
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
func (m *InotifyMonitor) Start(ctx context.Context) error {
	// 判断是否已经启动
	if m.Running {
		return errors.New("monitor 已经启动")
	}
	m.Running = true

	// 从文件读取监控路径
	paths, err := config.LoadMonitorPath("config/paths.list")
	if err != nil {
		return err
	}

	// 为audit设定监控路径
	err = m.AddPaths(paths)
	if err != nil {
		return err
	}

	defer syscall.Close(m.fd)

	// 获取监控路径，检查是否正确添加
	loadedPaths := m.GetPath()
	m.logger.Info("当前监控路径：", loadedPaths)

	// 创建一个缓冲区用于接收事件(可存放10个事件)
	// buf := make([]byte, syscall.SizeofInotifyEvent*10)
	buf := make([]byte, 4096)

	for {
		select {
		case <-ctx.Done():
			m.logger.Info("退出监控")
			return nil
		default:
			// 读取 inotify 事件
			n, err := syscall.Read(m.fd, buf)
			if err != nil {
				log.Fatalf("读取 inotify 事件失败: %v", err)
				continue
			}

			// 解析事件
			var offset uint32
			for offset <= uint32(n-syscall.SizeofInotifyEvent) {
				raw := (*syscall.InotifyEvent)(unsafe.Pointer(&buf[offset])) //  unsafe.Pointer将缓冲区中的数据转换为 syscall.InotifyEvent 指针
				// 打印事件类型(raw.Mask 是二进制掩码)
				// 使用与运算判别事件类型
				var eventType int    // 事件类型
				var eventPath string // 事件路径
				if raw.Mask&syscall.IN_OPEN == syscall.IN_OPEN {
					log.Printf("文件或目录打开: %d\n", raw.Wd)
					eventType = models.EventTypeOpen
				}
				if raw.Mask&syscall.IN_CREATE == syscall.IN_CREATE {
					log.Printf("文件或目录创建: %d\n", raw.Wd)
					eventType = models.EventTypeCreate
				}
				if raw.Mask&syscall.IN_MODIFY == syscall.IN_MODIFY {
					log.Printf("文件被修改: %d\n", raw.Wd)
					eventType = models.EventTypeModify
				}
				if raw.Mask&syscall.IN_DELETE == syscall.IN_DELETE {
					log.Printf("文件或目录删除: %d\n", raw.Wd)
					eventType = models.EventTypeDelete
				}
				if raw.Mask&syscall.IN_ATTRIB == syscall.IN_ATTRIB {
					log.Printf("文件权限或属性修改: %d\n", raw.Wd)
					eventType = models.EventTypeModify
				}
				if raw.Mask&syscall.IN_MOVE == syscall.IN_MOVE {
					log.Printf("文件或目录移动: %d\n", raw.Wd)
					eventType = models.EventTypeDelete
				}
				offset += syscall.SizeofInotifyEvent

				if path, ok := m.wdToPaths[int(raw.Wd)]; !ok { // 判断wd是否为监控的路径
					continue
				} else {
					eventPath = path
				}
				eventObj := &models.MonitorEvent{
					Id:        uuid.New().String(),
					EventType: eventType,  // 事件类型
					EventTime: time.Now(), // 事件发生时间
					Path:      eventPath,  // 路径
					Data:      "",         // 其他数据
				}
				var events []*models.MonitorEvent
				events = append(events, eventObj)
				go func() {
					if err := m.HandleEvent(ctx, events); err != nil {
						m.logger.Errorf("事件处理出错: %v", err)
					}
				}()
			}
		}
	}
}

// 停止监控
func (m *InotifyMonitor) Stop() error {
	m.pathMutex.Lock()
	defer m.pathMutex.Unlock()

	// 判断是否已经启动
	if !m.Running {
		return errors.New("monitor 未启动")
	}

	// 关闭文件描述符，停止监控
	err := syscall.Close(m.fd)
	if err != nil {
		return err
	}

	m.Running = false
	return nil
}

// 重启监控
func (m *InotifyMonitor) Restart(ctx context.Context) error {
	m.pathMutex.Lock()
	defer m.pathMutex.Unlock()

	// 停止
	err := m.Stop()
	if err != nil {
		return err
	}

	// 启动
	err = m.Start(ctx)
	if err != nil {
		return err
	}
	return nil
}

// 设置监控事件类型
func (m *InotifyMonitor) SetEventType() {
	m.event_type = syscall.IN_OPEN | syscall.IN_CREATE | syscall.IN_DELETE | syscall.IN_MODIFY | syscall.IN_ATTRIB | syscall.IN_MOVE
}

// 添加监控路径
func (m *InotifyMonitor) AddPaths(paths []string) error {
	m.pathMutex.Lock()
	defer m.pathMutex.Unlock()

	// TEST:检查路径是否存在
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

		log.Println("添加路径", path)

		// 使用inotify添加监控
		// wd, err := syscall.InotifyAddWatch(m.fd, path, syscall.IN_OPEN|syscall.IN_CREATE|syscall.IN_DELETE|syscall.IN_MODIFY|syscall.IN_ATTRIB|syscall.IN_MOVE)
		wd, err := syscall.InotifyAddWatch(m.fd, path, syscall.IN_ALL_EVENTS)

		if err != nil {
			log.Printf("添加监控路径失败: %s, 错误: %v", path, err)
			return err
		}

		m.paths[path] = wd     // 记录path->wd映射
		m.wdToPaths[wd] = path // 记录wd->path映射

		log.Println("监控路径成功", path, "-", wd)
	}
	return nil
}

// 删除监控路径
func (m *InotifyMonitor) RemovePath(paths []string) error {
	m.pathMutex.Lock()
	defer m.pathMutex.Unlock()

	for _, path := range paths {
		wd, ok := m.paths[path]
		if !ok {
			return errors.New("path 不存在")
		}
		delete(m.paths, path)
		// 从 inotify 中移除监控
		success, err := syscall.InotifyRmWatch(m.fd, uint32(wd))
		if err != nil {
			return err
		}
		log.Println("关闭inotify成功:", success)
	}

	return nil
}

// 获取监控路径
func (m *InotifyMonitor) GetPath() []string {
	m.pathMutex.Lock()
	defer m.pathMutex.Unlock()

	var paths []string
	for path := range m.paths {
		paths = append(paths, path)
	}
	return paths
}

// 处理事件
func (m *InotifyMonitor) HandleEvent(ctx context.Context, events []*models.MonitorEvent) error {
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

			// TODO:向服务端上报监控事件消息
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
func (m *InotifyMonitor) saveEventToFile(event *models.MonitorEvent) error {
	// 打开文件，如果不存在则创建，使用追加模式
	file, err := os.OpenFile(m.evenLogFile, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		m.logger.Error("[Monitor] 无法打开事件日志文件: ", err)
		return err
	}
	defer file.Close()

	// 使用 json.Encoder 更高效地进行编码和写入
	encoder := json.NewEncoder(file)
	if err := encoder.Encode(event); err != nil {
		m.logger.Error("事件写入文件时出错: ", err)
		return err
	}
	return nil
}
func (m *InotifyMonitor) saveErrorToFile(info string) error {
	// 打开文件，如果不存在则创建，使用追加模式
	file, err := os.OpenFile(m.errLogFile, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		return err
	}
	defer file.Close()

	// 写入 JSON 数据并在末尾追加换行符
	_, err = file.WriteString(info + "\n")
	return err
}
