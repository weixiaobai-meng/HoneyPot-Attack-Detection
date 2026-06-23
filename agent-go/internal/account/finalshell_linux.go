//go:build linux
// +build linux

package account

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"text/template"
	"time"
)

// FinalShell 配置结构体
type FinalshellConfig struct {
	ID         string `json:"id"`
	Host       string `json:"host"`
	UserName   string `json:"user_name"`
	Password   string `json:"password"`
	CreateTime int64  `json:"create_time"`
	ModfyTime  int64  `json:"modified_time"`
	Port       int    `json:"port"`
}

// 生成 FinalShell 配置
func (f *FinalshellConfig) generateConfig(username string, password string, host string, port int, path string) error {
	// 设置字段
	f.UserName = username
	f.Host = host
	f.Port = port
	f.ID = generateFinalshellRandomID(16) // 生成16位随机ID
	f.CreateTime = time.Now().UnixNano() / int64(time.Millisecond)
	if password == "" {
		f.Password = "P1sHUTIZXWxGQ72NBrtRJA==" // 固定密码
	} else {
		f.Password = password
	}

	// 读取模板文件内容
	templateFile := "config/templates/finalshell.txt" // 模板文件放在 templates 文件夹中
	templateData, err := os.ReadFile(templateFile)
	if err != nil {
		return fmt.Errorf("error reading template file %s: %v", templateFile, err)
	}

	// 创建文件路径
	filePath := filepath.Join(path, f.ID+"_finalshell_config.json")
	filePath = getUniqueFilePath(filePath)

	// 打开文件进行写入
	file, err := os.Create(filePath)
	if err != nil {
		return fmt.Errorf("error creating file %s: %v", filePath, err)
	}
	defer file.Close()

	// 使用模板替换进行动态填充
	tmpl, err := template.New("finalshellConfig").Parse(string(templateData))
	if err != nil {
		return fmt.Errorf("error parsing template: %v", err)
	}

	// 执行模板替换并写入文件
	err = tmpl.Execute(file, f)
	if err != nil {
		return fmt.Errorf("error executing template: %v", err)
	}

	return nil
}

// 查找 FinalShell 配置文件路径（适配Linux）
func (f *FinalshellConfig) FindFinalshellConfigPaths() (string, error) {
	// 先检查默认路径
	if path, found := f.checkDefaultPaths(); found {
		return path, nil
	}

	// 执行Linux `find` 命令查找 FinalShell 配置目录
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	cmd := exec.CommandContext(ctx, "find", os.Getenv("HOME"), "-type", "d", "-name", "conn")
	var out bytes.Buffer
	cmd.Stdout = &out

	err := cmd.Run()
	if err != nil {
		return "", fmt.Errorf("error executing find command: %v", err)
	}

	// 解析结果
	output := strings.TrimSpace(out.String())
	if output == "" {
		return "", fmt.Errorf("未找到FinalShell配置目录")
	}

	paths := strings.Split(output, "\n")
	for _, path := range paths {
		if f.hasJsonFile(path) {
			fmt.Println("Found valid FinalShell config directory:", path)
			return path, nil
		}
	}

	return "", fmt.Errorf("未找到包含 JSON 文件的 FinalShell 目录")
}

// 检查目录中是否有 .json 文件（FinalShell 的配置文件格式）
func (f *FinalshellConfig) hasJsonFile(path string) bool {
	files, err := os.ReadDir(path)
	if err != nil {
		return false
	}

	for _, file := range files {
		if !file.IsDir() && strings.HasSuffix(file.Name(), ".json") {
			return true
		}
	}
	return false
}

// 检查默认安装路径（适配Linux）
func (f *FinalshellConfig) checkDefaultPaths() (string, bool) {
	defaultPaths := []string{
		filepath.Join(os.Getenv("HOME"), ".finalshell", "conn"),
		"/opt/finalshell/conn",
		"/usr/local/finalshell/conn",
	}

	for _, path := range defaultPaths {
		if f.isDirectoryExists(path) && f.hasJsonFile(path) {
			fmt.Printf("通过默认路径找到配置目录: %s\n", path)
			return path, true
		}
	}
	return "", false
}

// 检查给定路径是否存在并且是一个目录
func (f *FinalshellConfig) isDirectoryExists(path string) bool {
	info, err := os.Stat(path)
	if err != nil {
		return false
	}
	return info.IsDir()
}
