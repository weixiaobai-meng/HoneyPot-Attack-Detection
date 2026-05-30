package pkg

import (
	"crypto/rand"
	"log"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/sirupsen/logrus"
)

var (
	WorkingDir     string // 工作目录，与程序的可执行文件路径无关
	ExuteDir       string // 程序所在路径
	ProjectRootDir string // 项目根目录
)

func InitProjectDir() error {
	var err error
	// 工作路径
	WorkingDir, err = os.Getwd()
	if err != nil {
		return err
	}

	// 可执行文件路径
	ExuteFilePath, err := os.Executable()
	ExuteDir = filepath.Dir(ExuteFilePath)

	// 项目根目录
	if strings.Contains(ExuteFilePath, string(filepath.Separator)+"cmd") {
		ProjectRootDir = filepath.Join(ExuteDir, "..") // 可执行文件所在目录(cmd)上层就是项目根目录
	} else {
		ProjectRootDir = ExuteDir // 可执行文件所在目录就是项目根目录
	}

	if err != nil {
		return err
	}
	return nil
}

// 检查邮箱是否合法
func IsValidEmail(email string) bool {
	// 使用正则表达式验证邮箱格式
	re := regexp.MustCompile(`^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$`)
	return re.MatchString(email)
}

// CreateDirIfNotExist 检查并创建项目根目录下的目录
func CreateDirIfNotExist(dir string) error {
	// 拼接绝对路径
	absDir := filepath.Join(ProjectRootDir, dir)

	// 判断目录是否存在
	if _, err := os.Stat(absDir); os.IsNotExist(err) {
		// 创建目录
		if err := os.Mkdir(absDir, os.ModePerm); err != nil {
			log.Fatalf("无法创建目录: %v", err)
			return err
		}
		log.Printf("创建目录: %s\n", absDir)
	}

	return nil
}

// 检查IP是否在白名单中
func IsInIPlist(ip string, list map[string]*net.IPNet) bool {
	// 判断是否是白名单中的单个IP
	if _, exists := list[ip+"/32"]; exists {
		return true
	}
	// 判断是否属于白名单中的某个网段
	parsedIP := net.ParseIP(ip)
	if parsedIP == nil {
		logrus.Errorf("invalid IP address: %s", ip)
		return false
	}
	for _, cidr := range list {
		if cidr.Contains(parsedIP) {
			return true
		}
	}
	return false
}

// GenerateApiKey 生成指定长度的随机 API Key
func GenerateApiKey(length int) (string, error) {
	var letters = []rune("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@%^&_")
	var sb strings.Builder
	for i := 0; i < length; i++ {
		// 使用 crypto/rand 生成安全随机数
		num, err := rand.Int(rand.Reader, big.NewInt(int64(len(letters))))
		if err != nil {
			return "", err
		}
		sb.WriteRune(letters[num.Int64()])
	}
	return sb.String(), nil
}
