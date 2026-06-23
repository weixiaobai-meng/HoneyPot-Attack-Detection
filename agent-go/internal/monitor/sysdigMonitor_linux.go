package monitor

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"strings"
	"sync"
	"syscall"
	"systemwire/agent/internal/config"
	"systemwire/agent/internal/models"
	pb "systemwire/agent/proto"
	"time"

	"github.com/google/uuid"
	"github.com/sirupsen/logrus"
)

// 监控类1：sysdig监控
type SysdigMonitor struct {
	pb_client   pb.AgentServiceClient // agent客户端
	logger      *logrus.Logger        // 日志记录器
	paths       map[string]bool       // 监控路径
	cmd         *exec.Cmd             // 用于运行 sysdig 的命令
	pathMutex   sync.Mutex            // 用于保护并发访问
	fileMutex   sync.Mutex            // 用于文件并发处理
	Running     bool                  // 监控是否正在运行
	evenLogFile string                // 文件监控记录路径
	errLogFile  string                // 报错日志
}

// 创建一个新的 SysdigMonitor 实例
func NewSysdigMonitor(client pb.AgentServiceClient) *SysdigMonitor {
	logger_obj := config.NewLogger(logrus.DebugLevel, "log/monitor.log")
	return &SysdigMonitor{
		pb_client:   client,
		paths:       make(map[string]bool), // 初始化监控路径
		logger:      logger_obj,
		evenLogFile: "log/file_event.log", // 文件监控事件
		errLogFile:  "log/file_err.log",   // 文件监控事件
	}
}

// 启动监控
func (m *SysdigMonitor) Start(ctx context.Context) error {
	if m.Running {
		return errors.New("监控已经在运行")
	}

	subCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	var wg sync.WaitGroup

	// 读取监控路径
	paths, err := config.LoadMonitorPath("config/paths.list")
	if err != nil {
		return err
	}
	m.AddPaths(paths)

	// 获取监控路径，检查是否正确添加
	loadedPaths := m.GetPath()
	m.logger.Info("当前监控路径：", loadedPaths)

	// 构造sysdig命令，监控指定的路径
	cmds := []string{
		"sysdig",
		"-p", "%evt.time %user.name %proc.name %proc.pid %proc.pname %evt.type %fd.name %evt.args %proc.cmdline %proc.cwd %evt.info",
	}

	// 添加路径过滤条件
	if len(m.paths) > 0 {
		var filters []string
		for path := range m.paths {
			// 使用 fd.name contains 过滤路径
			filters = append(filters, "fd.name contains "+path)
		}
		cmds = append(cmds, strings.Join(filters, " or "))
	} else {
		m.logger.Error("[Monitor] 未设置监控路径")
		return errors.New("未设置监控路径")
	}

	// 启动sysdig
	m.cmd = exec.Command("sudo", cmds...)

	stdout, err := m.cmd.StdoutPipe()
	if err != nil {
		return err
	}
	stderr, err := m.cmd.StderrPipe()
	if err != nil {
		return err
	}

	// 启动命令
	if err := m.cmd.Start(); err != nil {
		m.logger.Error(err)
		return err
	}

	m.Running = true
	m.logger.Info("[Monitor] Sysdig 监控已启动")

	// 异步处理 sysdig 输出
	go func() {
		defer wg.Done()
		m.handleOutput(subCtx, stdout, false, 10)
	}()
	wg.Add(1)
	go func() {
		defer wg.Done()
		go m.handleOutput(subCtx, stderr, true, 2)
	}()
	wg.Add(1)
	m.logger.Info("监控启动完成")

	<-ctx.Done()
	m.logger.Info("监控正在退出...")
	cancel()  // 停止子协程
	wg.Wait() // 等待协程完全退出
	return nil
}

// 停止监控
func (m *SysdigMonitor) Stop() error {
	fmt.Println("正在停止...")
	if !m.Running {
		return errors.New("监控未在运行")
	}

	// 向所有子进程发送 SIGTERM 信号，包括 sysdig
	if err := m.cmd.Process.Signal(syscall.SIGTERM); err != nil {
		return fmt.Errorf("无法发送终止信号: %v", err)
	}

	// 等待进程退出
	if err := m.cmd.Wait(); err != nil {
		return fmt.Errorf("等待进程退出时出错: %v", err)
	}

	fmt.Println("监控已停止")
	return nil
}

// 重启监控
func (m *SysdigMonitor) Restart(ctx context.Context) error {
	if err := m.Stop(); err != nil {
		return err
	}
	return m.Start(ctx)
}

// 批量添加监控路径
func (m *SysdigMonitor) AddPaths(paths []string) error {
	m.pathMutex.Lock()
	defer m.pathMutex.Unlock()

	for _, path := range paths {
		m.paths[path] = true
	}
	return nil
}

// 删除监控路径
func (m *SysdigMonitor) RemovePath(path string) error {
	m.pathMutex.Lock()         // 加锁
	defer m.pathMutex.Unlock() // 解锁

	if _, exists := m.paths[path]; !exists {
		return errors.New("路径不存在")
	}
	delete(m.paths, path)
	return nil
}

// 获取监控路径
func (m *SysdigMonitor) GetPath() []string {
	m.pathMutex.Lock()
	defer m.pathMutex.Unlock()

	var paths []string
	for path := range m.paths {
		paths = append(paths, path)
	}
	return paths
}

// 输出处理
func (m *SysdigMonitor) handleOutput(ctx context.Context, pipe io.ReadCloser, isError bool, workerLimit int) {
	defer pipe.Close()

	sem := make(chan struct{}, workerLimit) // 用于限制并发的信号量
	scanner := bufio.NewScanner(pipe)
	var events []*models.MonitorEvent
	for scanner.Scan() { // 每次处理一行(即一条输出)
		line := scanner.Text()
		m.logger.Info("[Monitor] Sysdig Output: ", line)
		if isError {
			m.logger.Info("[Monitor] Sysdig Error: ", line)
			err := m.saveErrorToFile(line)
			if err != nil {
				m.logger.Info("[Monitor] sysdig错误: ", err)
			}
		} else {
			// 输出解析
			eventObj, err := m.ParseEvent(line)
			if err != nil {
				m.logger.Info("[Monitor] 事件解析失败: ", err)
			}

			if eventObj == nil {
				// 空事件（如close）,不进行处理
				continue
			}

			// fmt.Println(event_obj)
			events = append(events, eventObj)
		}
	}
	// 事件处理
	sem <- struct{}{} // 占用一个 worker
	go func() {
		defer func() { <-sem }() // 释放一个 worker

		start := time.Now()
		if err := m.HandleEvent(ctx, events); err != nil {
			m.logger.Error("[Monitor] 处理 Sysdig 事件时出错: ", err)
		}

		elapsed := time.Since(start)
		if elapsed > time.Second {
			m.logger.Warnf("[Monitor] 事件处理耗时过长: %v", elapsed)
		}
	}()

	// 等待所有 goroutine 处理完成
	for i := 0; i < cap(sem); i++ {
		sem <- struct{}{} // 确保所有 worker 结束
	}

	if err := scanner.Err(); err != nil {
		m.logger.Error("[Monitor] 读取 Sysdig 输出时出错: ", err)
	}
}

// 解析事件
func (m *SysdigMonitor) ParseEvent(eventLine string) (*models.MonitorEvent, error) {
	// 示例事件处理逻辑，根据 sysdig 输出解析事件
	parts := strings.Fields(eventLine)
	if len(parts) < 10 {
		return nil, errors.New("事件格式错误")
	}
	var eventTypeId int
	// evtTime := parts[0]
	userName := parts[1]
	procName := parts[2]
	Pid := parts[3]
	procPname := parts[4]
	evtType := parts[5]
	fdName := parts[7]
	evtArgs := parts[8]
	// procCmdline := parts[8]
	// procCwd := parts[9]
	evtInfo := strings.Join(parts[10:], " ")

	// info := fmt.Sprintf("Time:%s, User:%s, Process:%s, PProcess:%s, Type:%s, FD:%s, Args:%s, Cmdline:%s, CWD:%s, Info:%s", evtTime, userName, procName, procPname, evtType, fdName, evtArgs, procCmdline, procCwd, evtInfo)

	switch evtType {
	case "open":
		eventTypeId = models.EventTypeOpen
	case "read":
		eventTypeId = models.EventTypeRead
	case "creat":
		eventTypeId = models.EventTypeCreate
	case "write", "modify":
		eventTypeId = models.EventTypeModify
	case "delete":
		eventTypeId = models.EventTypeDelete
	case "attr":
		eventTypeId = models.EventTypeModify
	case "move":
		eventTypeId = models.EventTypeDelete
	case "close":
		return nil, nil
	default:
		eventTypeId = models.EventTypeUnknown
		// m.logger.Info("未知的事件类型: ", evtType)
	}

	return &models.MonitorEvent{
		Id:            uuid.New().String(),
		EventType:     eventTypeId, //事件类型ID
		EventTypeName: evtType,     //事件类型名
		EventTime:     time.Now(),  // 事件发生时间
		User:          userName,
		Proc:          procName,
		Pid:           Pid,
		PProc:         procPname,
		Args:          evtArgs,
		Path:          fdName,  // 路径
		Data:          evtInfo, // 其他数据
	}, nil
}

// 处理事件
func (m *SysdigMonitor) HandleEvent(ctx context.Context, events []*models.MonitorEvent) error {
	// 记录告警至本地
	select {
	case <-ctx.Done():
		m.logger.Info("正在停止处理事件...")
		return ctx.Err()
	default:
		for _, event := range events {
			err := m.saveEventToFile(event)
			if err != nil {
				return err
			}
			// 推送告警至管理端(离线模式无需推送)
			if m.pb_client != nil {
				// TODO:推送至agent服务端
			}
		}
	}

	return nil
}

// 将事件写入到 JSON 文件中
func (m *SysdigMonitor) saveEventToFile(event *models.MonitorEvent) error {
	m.fileMutex.Lock()         // 加锁，确保并发安全
	defer m.fileMutex.Unlock() // 函数结束时解锁

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

func (m *SysdigMonitor) saveErrorToFile(info string) error {
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
