package pkg

import (
	"bytes"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/gin-gonic/gin"
	"github.com/sirupsen/logrus"
)

type CustomTextFormatter struct {
	TimestampFormat string
}

// 日志格式化
func (f *CustomTextFormatter) Format(entry *logrus.Entry) ([]byte, error) {
	var b bytes.Buffer

	// 设置颜色
	var levelColor int
	switch entry.Level {
	case logrus.DebugLevel, logrus.TraceLevel:
		levelColor = 36 // 青色
	case logrus.InfoLevel:
		levelColor = 32 // 绿色
	case logrus.WarnLevel:
		levelColor = 33 // 黄色
	case logrus.ErrorLevel, logrus.FatalLevel, logrus.PanicLevel:
		levelColor = 31 // 红色
	default:
		levelColor = 37 // 白色
	}

	// 设置时间戳
	timestamp := entry.Time.Format(f.TimestampFormat)
	// 设置日志级别和消息
	level := fmt.Sprintf("\x1b[%dm%-7s\x1b[0m", levelColor, entry.Level.String())
	msg := entry.Message

	// 组合日志输出
	fmt.Fprintf(&b, "%s %s %s\n", timestamp, level, msg)
	return b.Bytes(), nil
}

// 设置日志记录器
func SetupLogger() {
	// 判断是否存在 log 目录
	if err := CreateDirIfNotExist("log"); err != nil {
		logrus.Fatalf("[Config] 创建log目录出错: %v", err)
	}

	// 创建 Gin 日志文件
	ginLogFile, err := os.OpenFile("log/gin.log", os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0666)
	if err != nil {
		logrus.Fatalf("[Config] 打开log文件出错: %v", err)
	}

	// 设置 Gin 日志输出到文件和控制台
	gin.DefaultWriter = io.MultiWriter(ginLogFile, os.Stdout)

	ginLogFilePath := filepath.Join(ProjectRootDir, "log/gin.log")

	// 打开或创建 Logrus 日志文件
	logrusLogFile, err := os.OpenFile(ginLogFilePath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0666)
	if err != nil {
		fmt.Println("Failed to log to file, using default stderr")
		logrus.SetOutput(io.MultiWriter(os.Stderr, os.Stdout))
	} else {
		logrus.SetOutput(io.MultiWriter(logrusLogFile, os.Stdout))
	}

	// 设置自定义日志格式
	logrus.SetFormatter(&CustomTextFormatter{
		TimestampFormat: "2006-01-02 15:04:05",
	})

	// 设置日志级别
	logrus.SetLevel(logrus.InfoLevel)
}
