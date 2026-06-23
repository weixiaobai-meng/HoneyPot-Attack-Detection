package config

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	nested "github.com/antonfisher/nested-logrus-formatter"
	"github.com/go-ini/ini"
	"github.com/natefinch/lumberjack"
	"github.com/sirupsen/logrus"
)

var cfgFile *ini.File

type Config struct {
	AgentMode             string        // agent模式（online/offline）
	ServerAddress         string        // 服务端地址
	Token                 string        // token
	ReportInterval        time.Duration // 上报时间间隔
	RealTimeUpdate        bool          // 上报实时数据
	TLS                   *TLSConfig    // tls配置
	MonitorType           string        // 监控类型（audit/inotify/sysdig）
	MonitorListConfigPath string        // 监控列表的配置文件路径
	LogPath               string        // 日志路径
}

// NewConfig 初始化配置对象
func NewConfig() (*Config, error) {
	var err error

	// 读取配置文件 config.ini
	cfgFile, err = ini.Load("config/config.ini")
	if err != nil {
		return nil, err
	}

	cfg := &Config{}

	// 加载服务器信息
	if err := cfg.loadBaseConfig(); err != nil {
		return nil, err
	}

	// 加载 TLS 配置
	tlsConfig, err := LoadTLSConfig(cfg)
	if err != nil {
		return nil, err
	}

	cfg.TLS = tlsConfig

	return cfg, nil
}

// 加载基础信息
func (c *Config) loadBaseConfig() error {
	// 配置文件的必须字段
	mustKey := map[string]bool{
		"AgentMode":     true,
		"ServerAddress": true,
	}

	// 读取agent配置块
	agentSection, err := cfgFile.GetSection("AGENT")
	if err != nil {
		return err
	}
	for key, isMust := range mustKey {
		value, err := agentSection.GetKey(key)
		if err != nil {
			return err
		}
		if isMust && (value == nil || value.String() == "") {
			return errors.New("配置缺失：" + key)
		}
	}

	c.AgentMode = agentSection.Key("AgentMode").String()
	c.ServerAddress = agentSection.Key("ServerAddress").String()
	c.ReportInterval = time.Duration(agentSection.Key("ReportInterval").MustInt(5)) * time.Second
	c.RealTimeUpdate = agentSection.Key("RealTimeUpdate").MustBool(false)
	c.MonitorType = agentSection.Key("MonitorType").MustString("audit")
	c.MonitorListConfigPath = agentSection.Key("MonitorListConfigPath").MustString("config/paths.list")
	c.LogPath = agentSection.Key("LogPath").MustString("log/agent.log")
	c.Token = agentSection.Key("Token").MustString("")

	return nil
}

// NewLogger 创建日志记录器
func NewLogger(logLevel logrus.Level, logPath string) *logrus.Logger {
	Logger := logrus.New()

	// 设置日志级别
	Logger.SetLevel(logLevel)

	// 设置日志格式
	Logger.SetFormatter(&nested.Formatter{
		TimestampFormat: "2006-01-02 15:04:05",
		// FullTimestamp:   true,
		HideKeys: true,
		NoColors: true, // 关闭颜色输出
	})

	// 设置输出到标准输出（也可以输出到文件）
	if logPath != "" { // 同时输出到控制台和文件
		// 使用 lumberjack 实现日志轮转
		logFile := &lumberjack.Logger{
			Filename:   logPath,
			MaxSize:    10,   // 日志文件最大为10MB
			MaxBackups: 3,    // 保留最多3个备份日志文件
			MaxAge:     28,   // 最多保留28天
			Compress:   true, // 是否压缩旧的日志文件
		}
		// 同时输出到控制台和文件
		multiWriter := io.MultiWriter(os.Stdout, logFile)
		Logger.SetOutput(multiWriter)
	} else { // 只输出到控制台
		Logger.SetOutput(os.Stdout)
	}

	return Logger
}

// LoadMonitorPath 读取监控路径文件并更新
func LoadMonitorPath(filepath string) ([]string, error) {
	file, err := os.Open(filepath)
	if err != nil {
		return nil, fmt.Errorf("无法打开文件: %v", err)
	}
	defer file.Close()

	var paths []string
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line != "" {
			paths = append(paths, line)
		}
	}

	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("读取文件出错: %v", err)
	}

	return paths, nil
}

// SaveMonitorPath 保存监控路径到文件
func SaveMonitorPath(filepath string, paths []string) error {
	// 创建或覆盖文件
	file, err := os.Create(filepath)
	if err != nil {
		return fmt.Errorf("无法创建或覆盖文件: %v", err)
	}
	defer file.Close()

	// 使用缓冲写入
	writer := bufio.NewWriter(file)
	for _, path := range paths {
		_, err := writer.WriteString(path + "\n")
		if err != nil {
			return fmt.Errorf("写入文件失败: %v", err)
		}
	}

	// 刷新缓冲区
	err = writer.Flush()
	if err != nil {
		return fmt.Errorf("刷新文件缓冲区失败: %v", err)
	}

	return nil
}
