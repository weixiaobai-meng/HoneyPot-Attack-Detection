package monitor

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"systemwire/agent/internal/config"
	"systemwire/agent/internal/models"
	pb "systemwire/agent/proto"
	"time"

	"github.com/google/uuid"

	"github.com/sirupsen/logrus"
)

type AuditdMonitor struct {
	pb_client     pb.AgentServiceClient // agent客户端
	logger        *logrus.Logger        // 日志记录器
	evenLogFile   string                // 事件记录
	paths         map[string]bool       // 监控路径
	Running       bool                  // 监控是否正在运行
	monitorTag    string                // audit监控标签
	statePath     string                // 状态数据的文件路径
	lastQueryTime time.Time             // 上次查询日志时间
	wg            sync.WaitGroup        // wg
	mutex         sync.RWMutex          // 用于保护并发访问
}

type MonitorState struct {
	LastQueryTime time.Time `json:"last_query_time"`
}

// NewAuditdMonitor 创建一个新的 AuditdMonitor 实例
func NewAuditdMonitor(client pb.AgentServiceClient) *AuditdMonitor {
	logger_obj := config.NewLogger(logrus.DebugLevel, "log/monitor_audit.log")

	monitor := &AuditdMonitor{
		pb_client:   client,
		logger:      logger_obj,
		paths:       make(map[string]bool),
		Running:     false,
		monitorTag:  "lighting",
		statePath:   filepath.Join("log", "audit_monitor_state.json"),
		evenLogFile: "log/file_event_audit",
	}

	// 加载上次的查询时间
	if err := monitor.loadState(); err != nil {
		monitor.logger.Warnf("加载状态失败，将使用默认起始时间: %v", err)
	}
	if monitor.lastQueryTime.IsZero() {
		// 如果加载失败，使用一个默认的起始时间
		monitor.lastQueryTime = time.Now().Add(-24 * time.Hour)
	}

	return monitor
}

// 设置RPC客户端
func (m *AuditdMonitor) SetRPCClient(client pb.AgentServiceClient) {
	m.pb_client = client
}

// 加载状态数据
func (m *AuditdMonitor) loadState() error {
	data, err := os.ReadFile(m.statePath)
	if err != nil {
		if os.IsNotExist(err) {
			return nil // 文件不存在不是错误
		}
		return fmt.Errorf("读取状态文件失败: %v", err)
	}

	var state MonitorState
	if err := json.Unmarshal(data, &state); err != nil {
		return fmt.Errorf("解析状态文件失败: %v", err)
	}

	m.mutex.Lock()
	m.lastQueryTime = state.LastQueryTime
	m.mutex.Unlock()

	return nil
}
func (m *AuditdMonitor) saveState() error {
	m.mutex.RLock()
	state := MonitorState{
		LastQueryTime: m.lastQueryTime,
	}
	m.mutex.RUnlock()

	data, err := json.Marshal(state)
	if err != nil {
		return fmt.Errorf("序列化状态失败: %v", err)
	}

	// 原子写入文件
	tempFile := m.statePath + ".tmp"
	if err := os.WriteFile(tempFile, data, 0644); err != nil {
		return fmt.Errorf("写入临时状态文件失败: %v", err)
	}

	if err := os.Rename(tempFile, m.statePath); err != nil {
		return fmt.Errorf("更新状态文件失败: %v", err)
	}

	return nil
}

// Start 启动监控，读取 audit 日志
func (m *AuditdMonitor) Start(ctx context.Context) error {
	// if m.Running {
	// 	m.logger.Warn("监控已经在运行中")
	// 	return nil
	// }

	// 判断auditd是否正在运行
	isActivate, err := isAuditdRunning()
	if err != nil {
		return errors.New("检测audit状态出错: " + err.Error())
	}

	done := make(chan bool, 1)

	// 启动 auditd 服务
	if !isActivate {
		cmd := exec.Command("systemctl", "start", "auditd")
		if err := cmd.Run(); err != nil {
			return fmt.Errorf("启动 auditd 失败: %v", err)
		}
	}

	// 读取并添加监控文件路径
	paths, err := config.LoadMonitorPath("config/paths.list")
	if err != nil {
		return err
	}
	err = m.AddPaths(paths)
	if err != nil {
		return err
	}

	// 启动一个 goroutine 来读取审计日志
	m.Running = true
	m.wg.Add(1)
	go func() {
		defer m.wg.Done()
		if err := m.handlrAusearch(ctx); err != nil {
			m.logger.Errorf("读取事件出错: %v", err)
		}
		done <- true
	}()

	return nil
}

// Stop 停止监控
func (m *AuditdMonitor) Stop() error {
	if !m.Running {
		return errors.New("监控未在运行")
	}

	// 停止 auditd 服务
	cmd := exec.Command("systemctl", "stop", "auditd")
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("停止 auditd 失败: %v", err)
	}

	m.Running = false
	return nil
}

// Restart 重启监控
func (m *AuditdMonitor) Restart(ctx context.Context) error {
	// TODO:重启
	return nil
}

// AddPaths 添加监控路径
func (m *AuditdMonitor) AddPaths(paths []string) error {
	// m.mutex.Lock()
	// defer m.mutex.Unlock()

	// 添加审计规则
	for _, path := range paths {
		if _, exists := m.paths[path]; exists {
			m.logger.Info("路径已存在:" + path)
			continue
		}

		// 使用 auditctl 添加监控路径
		cmd := exec.Command("sudo", "/usr/sbin/auditctl", "-w", path, "-p", "rwxa", "-k", m.monitorTag)
		var stderr bytes.Buffer
		cmd.Stderr = &stderr
		if err := cmd.Run(); err != nil {
			if strings.Contains(stderr.String(), "Rule exists") {
				m.logger.Infof("规则: %s 已存在", path)
			} else {
				return fmt.Errorf("添加规则: %s 失败:%v", path, cmd.Stderr)
			}
		}

		m.paths[path] = true
	}

	return nil
}

// RemovePath 删除监控路径
func (m *AuditdMonitor) RemovePath(paths []string) error {
	m.mutex.Lock()
	defer m.mutex.Unlock()

	// 筛选出需要存在的路径
	for _, path := range paths {
		if _, exists := m.paths[path]; !exists {
			return errors.New("路径不存在")
		}
		// 使用 auditctl 移除监控路径
		cmd := exec.Command("auditctl", "-W", path)
		if err := cmd.Run(); err != nil {
			return fmt.Errorf("删除审计规则失败: %v", err)
		}
		delete(m.paths, path)
	}

	return nil
}

// GetPath 获取监控路径
func (m *AuditdMonitor) GetPath() []string {
	m.mutex.Lock()
	defer m.mutex.Unlock()

	paths := make([]string, 0, len(m.paths))
	for path := range m.paths {
		paths = append(paths, path)
	}

	return paths
}

// 使用ausearch获取告警
func (m *AuditdMonitor) handlrAusearch(ctx context.Context) error {
	// 查询循环计时器
	ticker := time.NewTicker(10 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return nil

		case <-ticker.C:
			// 查询并处理日志
			if err := m.queryAndProcessAuditLogs(ctx); err != nil {
				m.logger.Errorf("处理审计日志失败: %v", err)
			}
		}
	}
}

// 查询ausearch
func (m *AuditdMonitor) queryAndProcessAuditLogs(ctx context.Context) error {
	m.mutex.Lock()
	startTime := m.lastQueryTime
	m.mutex.Unlock()

	currentTime := time.Now()

	// 查询
	cmd := exec.Command("sudo", "/usr/sbin/ausearch",
		"-k", m.monitorTag,
		"-ts", startTime.Format("01/02/2006"), startTime.Format("15:04:05"),
		"-te", currentTime.Format("01/02/2006"), currentTime.Format("15:04:05"),
		"-i")
	fmt.Println(cmd)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	if err := cmd.Run(); err != nil {
		// 无记录
		if strings.TrimSpace(stderr.String()) == "<no matches>" {
			//m.logger.Debugf("在指定时间段未找到审计记录：%v - %v", startTime, currentTime)
			// 即使没有找到记录，也需要更新最后查询时间
			m.mutex.Lock()
			m.lastQueryTime = currentTime
			m.mutex.Unlock()
		} else {
			return fmt.Errorf("执行ausearch命令失败: %v\nstderr: %s", err, stderr.String())
		}
	}

	// 记录查询状态
	m.mutex.Lock()
	m.lastQueryTime = currentTime
	m.mutex.Unlock()
	if err := m.saveState(); err != nil {
		m.logger.Errorf("保存状态失败: %v", err)
		// 继续处理，不返回错误
	}

	//fmt.Println(stdout.String())
	//fmt.Println(stderr.String())

	// 处理执行结果
	records, err := m.ParseAuditLogs(stdout.String())
	if err != nil {
		return err
	}

	// 处理事件
	var events []*models.MonitorEvent
	for _, record := range records {
		if keyValues, ok := record.Records["SYSCALL"]; ok {
			event := &models.MonitorEvent{
				Id:            uuid.New().String(),
				EventType:     models.ActionStrToType(keyValues["syscall"]),
				EventTypeName: keyValues["syscall"],
				EventTime:     record.Time,
				User:          keyValues["auid"],
				Proc:          keyValues["exe"],
				Pid:           keyValues["pid"],
				PProc:         keyValues["ppid"],
				Args:          record.Records["PROCTITLE"]["proctitle"], // 命令和参数
				Path:          m.getTriggerPath(record),                 // 触发路径
				Data:          record.RawData,                           // 原始数据
			}
			events = append(events, event)
		}
	}

	// 处理事件
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		if err := m.HandleEvent(ctx, events); err != nil {
			m.logger.Errorf("处理事件失败: %v", err)
		}
	}()

	return nil
}

// 解析Audit原始日志
func (m *AuditdMonitor) ParseAuditLogs(rawLog string) ([]*models.AuditRecord, error) {
	var records []*models.AuditRecord
	//var currentrRecord *models.AuditRecord

	// 分割日志组
	groups := strings.Split(rawLog, "----")

	for _, group := range groups {
		group = strings.TrimSpace(group)
		if group == "" {
			// 过滤空行
			continue
		}
		record := &models.AuditRecord{
			Records: make(map[string]map[string]string), // 初始化
			RawData: group,
		}

		// 处理一行
		lines := strings.Split(group, "\n")
		for _, line := range lines {
			line = strings.TrimSpace(line)
			if line == "" {
				continue
			}

			// 解析类型
			typeMatch := regexp.MustCompile(`type=(\w+)`).FindStringSubmatch(line)
			if len(typeMatch) < 2 {
				continue
			}
			eventType := typeMatch[1]

			// 解析时间和序列号
			if record.Time.IsZero() {
				startIdx := strings.Index(line, "(")
				endIdx := strings.Index(line, ")")
				// 如果找到括号
				if startIdx != -1 && endIdx != -1 && endIdx > startIdx {
					// 提取括号中的内容
					content := line[startIdx+1 : endIdx]

					// 查找冒号的位置
					colonIdx := strings.LastIndex(content, ":")
					if colonIdx != -1 {
						// 拆分时间部分和序号部分
						timeStr := content[:colonIdx]
						seqNumber := content[colonIdx+1:]
						if t, err := time.Parse("01/02/2006 15:04:05.000", timeStr); err == nil {
							record.Time = t
						} else {
							m.logger.Errorf("时间解析出错:%v", err)
						}
						record.Serial = seqNumber
					}
				}
			}

			// 解析事件细节
			keyValuePart := strings.Split(line, ":")[4] // 最后的键值对部分
			var keyValuePairs []string
			if eventType == "PROCTITLE" || eventType == "SOCKADDR" {
				keyValuePairs = append(keyValuePairs, keyValuePart) // 如:"proctitle=/usr/sbin/auditctl -w /home/cly/test -p rwxa -k lighting "
			} else {
				keyValuePairs = strings.Fields(keyValuePart) // 如:"arch=x86_64 syscall=sendto success=yes exit=1080 "
			}
			kv := make(map[string]string)
			for _, detail := range keyValuePairs {
				detail = strings.TrimSpace(detail)     // 去空格
				keyValue := strings.Split(detail, "=") // 拆成key和value
				if len(keyValue) < 2 {
					continue
				}
				kv[keyValue[0]] = keyValue[1] // 存储
			}
			record.Records[eventType] = kv // 将类型的kvs存储到对应的type下

			if record.Serial != "" {
				records = append(records, record)
			}
		}
	}
	return records, nil
}

// 获取触发的路径
func (m *AuditdMonitor) getTriggerPath(record *models.AuditRecord) string {
	paths := make([]string, 0)
	// PROCTITLE
	cmdLine := record.Records["PROCTITLE"]["proctitle"]
	parts := strings.Fields(cmdLine)
	for _, part := range parts {
		if strings.Contains(part, "/") || strings.Contains(part, ".") {
			paths = append(paths, part)
		}
	}

	// CWD
	var cwd string
	if path, ok := record.Records["CWD"]; ok {
		cwd = path["cwd"]
		paths = append(paths, cwd)
	}

	// PATH
	if kvs, ok := record.Records["PATH"]; ok {
		path := kvs["name"]
		if path == "." {
			// 在CWD路径下执行
		} else {
			path = cwd + "/" + path
			paths = append(paths, path)
		}
	}

	// 判断是哪一个
	for _, path := range paths { // 解析出的path
		for mPath := range m.paths { // 监控路径列表
			if strings.Contains(path, mPath) {
				// 如果记录中包含被监控路径
				return path
			}
		}

	}
	return paths[len(paths)-1]
}

// HandleEvent 处理审计事件
func (m *AuditdMonitor) HandleEvent(ctx context.Context, events []*models.MonitorEvent) error {
	// 确保事件日志目录存在
	logDir := filepath.Join("log")
	if err := os.MkdirAll(logDir, 0755); err != nil {
		return fmt.Errorf("创建日志目录失败: %v", err)
	}

	// 按日期生成日志文件名
	logFile := m.evenLogFile + "-" + time.Now().Format("2006-01-02") + ".log"
	// 打开日志文件（追加模式）
	f, err := os.OpenFile(logFile, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		return fmt.Errorf("打开日志文件失败: %v", err)
	}
	defer f.Close()

	select {
	case <-ctx.Done():
		m.logger.Info("正在停止处理事件...")
		return ctx.Err()
	default:
		var eventMessage *pb.MonitorEvent
		for _, event := range events {
			//m.logger.Println(event)
			err := m.saveEventToFile(f, event)
			if err != nil {
				return err
			}
			// 推送告警至管理端(离线模式无需推送)
			if m.pb_client != nil {
				eventMessage = event.GetEventPb()
				fb, err := m.pb_client.ReportMonitorEvent(context.Background(), eventMessage)
				if err != nil {
					return fmt.Errorf("告警推送出错, %v", err)
				} else if !fb.Successful {
					m.logger.Infof("告警推送失败, %v", fb.Message)
				} else {
					m.logger.Infof("告警推送成功, %v", fb.Message)
				}
				return nil
			}
		}
	}

	return nil
}

// 将事件写入到 JSON 文件中
func (m *AuditdMonitor) saveEventToFile(file *os.File, event *models.MonitorEvent) error {
	// 使用 json.Encoder 更高效地进行编码和写入
	encoder := json.NewEncoder(file)
	if err := encoder.Encode(event); err != nil {
		m.logger.Error("事件写入文件时出错: ", err)
		return err
	}
	return nil
}

// 判断Audit是否安装
func isAuditdInstalled() (bool, error) {
	cmd := exec.Command("dpkg", "-l") // 适用于 Debian/Ubuntu 系统
	output, err := cmd.CombinedOutput()
	if err != nil {
		return false, fmt.Errorf("failed to run dpkg: %v", err)
	}

	// 检查是否包含 auditd
	if strings.Contains(string(output), "auditd") {
		return true, nil
	}

	return false, nil
}

// 判断Audit是否启动
func isAuditdRunning() (bool, error) {
	installed, err := isAuditdInstalled()
	if err != nil {
		return false, fmt.Errorf("检测audit安装失败: %v", err)
	}
	if !installed {
		return false, errors.New("检测到audit未安装")
	}

	cmd := exec.Command("systemctl", "is-active", "auditd")
	output, err := cmd.Output()
	if err != nil {
		status := strings.TrimSpace(string(output))
		if status == "inactive" {
			return false, nil
		}
		return false, fmt.Errorf("检测audit启动失败: %v, output: %s", err, string(output))
	}

	// 判断是否返回 active
	status := strings.TrimSpace(string(output))
	if status == "active" {
		return true, nil
	}

	return false, nil
}

func (m *InotifyMonitor) SetRPCClient(client pb.AgentServiceClient) {
	m.pb_client = client
}
