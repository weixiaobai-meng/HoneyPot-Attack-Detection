package urlalert

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"os"
	"os/signal"
	"path/filepath"
	"sync"
	"syscall"
	"systemwire/agent/internal/config"
	pb "systemwire/agent/proto"
	"time"

	"github.com/fsnotify/fsnotify"
	"github.com/sirupsen/logrus"
)

var (
	urlLogPath = "/home/cly/agent-go/log/url_alert.json" // 寄生蜜点告警日志路径
)

// 定义结构体来映射JSON数据
type UrlAlertMessage struct {
	TimeStamp   uint64          `json:"time"`
	Ip          string          `json:"ip"`
	Fingerprint string          `json:"fingerprint"`
	Details     json.RawMessage `json:"details"`
}

// 寄生蜜点告处理器
type UrlMonitor struct {
	pb_client pb.AgentServiceClient // agent客户端
	logger    *logrus.Logger        // 日志记录器
}

func NewUrlMonitor(client pb.AgentServiceClient) *UrlMonitor {
	return &UrlMonitor{
		pb_client: client,                                                 // 绑定客户端
		logger:    config.NewLogger(logrus.DebugLevel, "log/monitor.log"), // 日志记录器
	}
}

// 启动寄生蜜点告警监视
func (um *UrlMonitor) Start(ctx context.Context) {
	watcher, err := fsnotify.NewWatcher()
	if err != nil {
		log.Fatal(err)
	}
	defer watcher.Close()

	// 捕获系统信号
	signalChan := make(chan os.Signal, 1)
	signal.Notify(signalChan, syscall.SIGINT, syscall.SIGTERM)

	// 监控文件所在的目录
	err = watcher.Add(filepath.Dir(urlLogPath))
	if err != nil {
		log.Fatal(err)
	}

	go func() {
		for {
			select {
			case event, ok := <-watcher.Events:
				if !ok {
					return
				}
				if event.Op&fsnotify.Write == fsnotify.Write && event.Name == urlLogPath {
					err = um.processLog()
					if err != nil {
						um.logger.Println("处理日志文件出错:", err)
					}
				}
			case err, ok := <-watcher.Errors:
				if !ok {
					return
				}
				um.logger.Println("文件监控错误:", err)
				// case <-ctx.Done():
				// 	um.logger.Println("上下文取消，停止监控")
				return
			case sig := <-signalChan:
				um.logger.Printf("收到系统信号: %v，停止监控", sig)
				return
			}
		}
	}()

	log.Println("监控文件路径:", urlLogPath)
	<-signalChan
}

func (um *UrlMonitor) processLog() error {
	// 读取json文件
	data, err := um.readJSONFile(urlLogPath)
	if err != nil {
		fmt.Println("Error reading file:")
		return err
	}

	// 解析json数据
	alerts, err := um.parseJSON(data)
	if err != nil {
		fmt.Println("Error parsing JSON:")
		return err
	}

	for _, alert := range alerts {
		fmt.Printf("Time: %d\n", alert.TimeStamp)
		fmt.Printf("Ip: %s\n", alert.Ip)
		fmt.Printf("Fingerprint: %s\n", alert.Fingerprint)
		fmt.Printf("Details: %s\n", alert.Details)
	}

	// 推送告警
	go um.sendUrlAlert(alerts)
	return nil
}

// 读取Json文件
func (um *UrlMonitor) readJSONFile(filePath string) ([]byte, error) {
	var lastModTime time.Time
	for {
		// 获取文件属性，检查更改事件
		fileInfo, err := os.Stat(filePath)
		if err != nil {
			return nil, err
		}

		// 如果文件被修改了，则读取文件
		if fileInfo.ModTime() != lastModTime {
			// 打开文件
			file, err := os.OpenFile(filePath, os.O_RDONLY, 0666)
			if err != nil {
				fmt.Println("打开文件错误:", err)
				return nil, err
			}
			defer file.Close()

			// 获取共享锁
			// err = syscall.Flock(int(file.Fd()), syscall.LOCK_SH)
			if err != nil {
				fmt.Println("上锁错误:", err)
				return nil, err
			}
			// defer syscall.Flock(int(file.Fd()), syscall.LOCK_UN)

			// 读取数据
			data, err := io.ReadAll(file)
			if err != nil {
				fmt.Println("读取文件错误:", err)
				return nil, err
			}

			return data, nil
		}
	}
}

// 解析JSON数据
func (um *UrlMonitor) parseJSON(data []byte) ([]UrlAlertMessage, error) {
	var alerts []UrlAlertMessage
	err := json.Unmarshal(data, &alerts)
	if err != nil {
		return nil, err
	}
	return alerts, nil
}

// 发送告警
func (um *UrlMonitor) sendUrlAlert(alerts []UrlAlertMessage) error {
	var wg sync.WaitGroup

	for _, alert := range alerts {
		wg.Add(1)
		go func(alert UrlAlertMessage) {
			defer wg.Done()
			detailsByte, err := json.Marshal(alert.Details)
			if err != nil {
				fmt.Println("URL告警解析出错，Details转字符串错误:", err)
				return
			}
			// 每个 goroutine 内部单独创建 alert_pb 以避免并发问题
			alert_pb := &pb.UrlAlertEvent{
				TimeStamp:   alert.TimeStamp,
				Ip:          alert.Ip,
				Fingerprint: alert.Fingerprint,
				Details:     string(detailsByte),
			}

			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()

			// 调用 pb_client 报告 URL 事件
			fb, err := um.pb_client.ReportUrlEvent(ctx, alert_pb)
			if err != nil || !fb.Successful {
				um.logger.Println("Url告警推送失败:", err)
				// TODO: 重试，或者将失败的告警记录到日志或数据库中
			}
		}(alert)
	}

	wg.Wait() // 等待所有 goroutine 完成
	return nil
}
