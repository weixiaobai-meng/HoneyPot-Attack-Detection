//go:build windows
// +build windows

package account

import (
	"bytes"
	"context"
	"encoding/base64"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"systemwire/agent/pkg"
	"text/template"
	"time"
)

// Xshell 配置结构体
type XshellConfig struct {
	Host     string
	Port     int
	Username string
	Password string
}

// 生成 Xshell 配置
func (x *XshellConfig) generateXshellConfig(username, host string, port int, password string, path string) error {
	// fmt.Println(x.isDirectoryExists("C:/Users/Teri/Documents"))

	// 密码
	if password == "" {
		password = pkg.GenerateXshellPassword(16)
	}

	// 对密码进行 Base64 编码
	encodedPassword := base64.StdEncoding.EncodeToString([]byte(password))

	// 设置字段
	x.Host = host
	x.Port = port
	x.Username = username
	x.Password = encodedPassword
	// x.Protocol = "SSH"

	// 读取模板文件内容
	templateFile := "config/templates/xshell.txt" // 模板文件放在 templates 文件夹中
	templateData, err := os.ReadFile(templateFile)
	if err != nil {
		return fmt.Errorf("error reading template file %s: %v", templateFile, err)
	}

	// 使用文本模板的内容生成配置文件
	// 创建文件路径
	prefix := "公司"
	configName := pkg.GenerateXshellConfigFilename(prefix)
	filePath := filepath.Join(path, configName)
	filePath = getUniqueFilePath(filePath)

	// 创建文件进行写入
	file, err := os.Create(filePath)
	if err != nil {
		return fmt.Errorf("error creating file %s: %v", filePath, err)
	}
	defer file.Close()

	// 使用模板替换进行动态填充
	tmpl, err := template.New("config").Parse(string(templateData))
	if err != nil {
		return fmt.Errorf("error parsing template: %v", err)
	}

	// 执行模板替换并写入文件
	err = tmpl.Execute(file, x)
	if err != nil {
		return fmt.Errorf("error executing template: %v", err)
	}
	return nil
}

// 检查给定路径是否存在并且是一个目录
func (x *XshellConfig) isDirectoryExists(path string) bool {
	info, err := os.Stat(path) //获取指定路径的文件或目录的信息
	if err != nil {
		// 如果返回的错误是因为文件或目录不存在
		if os.IsNotExist(err) {
			return false
		}
		// 其他错误直接返回
		fmt.Println("Error:", err)
		return false
	}
	// 检查是否为目录
	return info.IsDir()
}

// 标准化驱动器路径，确保除C盘外以 "\" 结尾
func normalizeDrive(drive string) string {
	// 如果驱动器路径不以 "\" 结尾，则追加一个
	if !strings.HasSuffix(drive, "\\") {
		return drive + "\\"
	}
	return drive
}

// 执行 PowerShell 命令查找含有 Xshell\Sessions 特定路径
func (x *XshellConfig) findXshellSessions(drive string) ([]string, error) {
	drive = normalizeDrive(drive)
	psCmd := fmt.Sprintf("[Console]::OutputEncoding = [System.Text.Encoding]::UTF8; Get-ChildItem -Path %s -Directory -ErrorAction SilentlyContinue -Recurse | Where-Object { $_.FullName -match 'Xshell\\\\Sessions' } | Select-Object -ExpandProperty FullName", drive)
	cmd := exec.Command("powershell", "-Command", psCmd)
	//cmd := exec.Command("powershell", "-NoProfile", "-Command", psCmd)
	var out bytes.Buffer
	var stderr bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &stderr

	err := cmd.Run()
	if err != nil {
		// 仅在 PowerShell 报错时打印详细信息
		if stderr.Len() > 0 {
			return nil, fmt.Errorf("PowerShell 执行错误: %v\n%s", err, stderr.String())
		}
	}

	// 解析结果
	output := strings.TrimSpace(out.String())
	if output == "" {
		return nil, nil
	}
	return strings.FieldsFunc(output, func(r rune) bool {
		return r == '\r' || r == '\n'
	}), nil
}

// 检查目录中是否有 .xsh 文件
func (x *XshellConfig) hasXshFile(path string) bool {
	//递归遍历指定路径下的所有文件和目录。
	err := filepath.Walk(path, func(fpath string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if !info.IsDir() && strings.HasSuffix(info.Name(), ".xsh") {
			return fmt.Errorf("found .xsh file") // 跳出文件遍历
		}
		return nil
	})
	return err != nil // 如果找到 .xsh 文件，则返回 true
}

// 查找Xshell配置文件路径（混合扫描方案）
func (x *XshellConfig) FindXshellConfigPaths() (string, error) {
	// 新增默认路径检查（优先快速通道）
	if path, found := x.checkDefaultPaths(); found {
		return path, nil
	}

	// 获取驱动器列表
	drives, err := GetDriveList()
	if err != nil {
		return "", fmt.Errorf("error getting drive list: %v", err)
	}

	// 智能扫描控制
	const (
		timeout     = 20 * time.Second
		concurrency = 2
	)
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	resultChan := make(chan string, len(drives))
	sem := make(chan struct{}, concurrency)

	// 并行扫描优化
	for _, drive := range drives {
		go func(d string) {
			sem <- struct{}{}
			defer func() { <-sem }()
			// 针对 C 盘的处理
			if d == "C:" {
				// 尝试查找可访问的 Xshell Sessions 目录
				paths, err := x.findAccessibleXshellSessions(d)
				if err != nil {
					fmt.Printf("Scan %s error: %v\n", d, err)
					return
				}

				for _, path := range paths {
					if x.hasXshFile(path) {
						resultChan <- path
						return
					}
				}
			} else {
				// 针对其他盘的处理
				paths, err := x.findXshellSessions(d)
				if err != nil {
					fmt.Printf("Scan %s error: %v\n", d, err)
					return
				}

				for _, path := range paths {
					if x.hasXshFile(path) {
						resultChan <- path
						return
					}
				}
			}
		}(drive)
	}

	// 结果等待
	select {
	case path := <-resultChan:
		fmt.Println("Found valid Xshell config directory:", path)
		return path, nil
	case <-ctx.Done():
		return "", fmt.Errorf("扫描超时，未找到有效路径")
	}
}

// 查找可访问的 Xshell Sessions 目录（C盘专用）
func (x *XshellConfig) findAccessibleXshellSessions(drive string) ([]string, error) {
	// 使用 PowerShell 查找可能的 Xshell Sessions 目录
	psCmd := fmt.Sprintf("[Console]::OutputEncoding = [System.Text.Encoding]::UTF8; Get-ChildItem -Path %s -Directory -ErrorAction SilentlyContinue -Recurse | Where-Object { $_.FullName -match 'Xshell\\\\Sessions' } | Select-Object -ExpandProperty FullName", drive)

	cmd := exec.Command("powershell", "-Command", psCmd)
	var out bytes.Buffer
	var stderr bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &stderr

	err := cmd.Run()
	if err != nil {
		// 仅在 PowerShell 报错时打印详细信息
		if stderr.Len() > 0 {
			return nil, fmt.Errorf("PowerShell 执行错误: %v\n%s", err, stderr.String())
		}
	}

	// 解析结果
	output := strings.TrimSpace(out.String())
	if output == "" {
		return nil, nil
	}
	return strings.FieldsFunc(output, func(r rune) bool {
		return r == '\r' || r == '\n'
	}), nil
}

// 检查默认安装路径
func (x *XshellConfig) checkDefaultPaths() (string, bool) {
	defaultPaths := []string{
		filepath.Join(os.Getenv("USERPROFILE"), "Documents", "NetSarang Computer", "Xshell", "Sessions"),
		filepath.Join(os.Getenv("PROGRAMFILES"), "NetSarang", "Xshell", "Sessions"),
		filepath.Join(os.Getenv("ProgramFiles(x86)"), "NetSarang", "Xshell", "Sessions"),
		`C:\Xshell\Sessions`,
	}

	for _, path := range defaultPaths {
		if x.isDirectoryExists(path) && x.hasXshFile(path) {
			fmt.Printf("通过默认路径找到配置目录: %s\n", path)
			return path, true
		}
	}
	return "", false
}
