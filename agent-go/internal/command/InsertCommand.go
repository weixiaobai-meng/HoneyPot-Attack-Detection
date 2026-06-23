package command

import (
	"bufio"
	"fmt"
	"math/rand"
	"os"
	"path/filepath"
	"strings"
)

// CommandType 表示要插入的命令类型
type CommandType string

const (
	FileAccess CommandType = "file_access"
	URLAccess  CommandType = "url_access"
	SSHKey     CommandType = "ssh_key"
)

var fileTemplates = []string{
	"cat {target}",        // 查看文件内容
	"head -n 10 {target}", // 查看文件前 10 行
	"tail -n 10 {target}", // 查看文件后 10 行
	"stat {target}",       // 查看文件属性
	"less {target}",       // 使用 less 查看文件
}
var directoryTemplates = []string{
	"cd {directory} && ls",          // 列出目录内容
	"cd {directory} && cat {file}",  // 切换到目录并访问某文件
	"cd {directory} && stat {file}", // 切换到目录并查看文件属性
}

//var fileAccessTemplates = []string{
//	"cat {target}",                 // 查看文件内容
//	"head -n 10 {target}",          // 查看文件前 10 行
//	"tail -n 10 {target}",          // 查看文件后 10 行
//	"stat {target}",                // 查看文件属性
//	"less {target}",                // 使用 less 打开文件
//	"cd {directory} && ls",         // 列出目录内容
//	"cd {directory} && cat {file}", // 切换到目录并查看某文件
//}

var urlAccessTemplates = []string{
	"curl {target}",                      // 使用 curl 访问 URL
	"wget {target} -O /tmp/dump",         // 使用 wget 下载 URL 内容
	"http {target}",                      // 使用 httpie 访问 URL
	"curl -I {target}",                   // 查看 URL 的头信息
	"curl {target} > /tmp/response.html", // 将 URL 的内容保存到文件
}

var sshKeyTemplates = []string{
	"cat {target}",                       // 查看密钥内容
	"chmod 600 {target}",                 // 修改密钥权限
	"ssh-keygen -l -f {target}",          // 检查密钥指纹
	"ssh-agent bash && ssh-add {target}", // 添加密钥到 SSH Agent
}

// InsertCommands 将多个假命令插入到给定的.bash_history文件的指定位置
func InsertCommands(line int, isReverse bool, commandType CommandType, honeyPoints []string) error {
	//打开.bash_history文件
	filePath := filepath.Join(os.Getenv("HOME"), ".bash_history")
	file, err := os.Open(filePath)
	if err != nil {
		return fmt.Errorf("failed to open file: %w", err)
	}
	defer file.Close()

	//将history所有行读入内存
	lines := []string{}
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		lines = append(lines, scanner.Text())
	}
	if err := scanner.Err(); err != nil {
		return fmt.Errorf("failed to read file: %w", err)
	}

	//确定插入索引
	var index int
	if isReverse {
		index = len(lines) - line
		if index < 0 || index > len(lines) {
			return fmt.Errorf("invalid reverse line number: %d", line)
		}
	} else {
		index = line - 1
		if index < 0 || index > len(lines) {
			return fmt.Errorf("invalid line number: %d", line)
		}
	}

	//生成多个假命令
	fakeCommands := generateFakeCommands(commandType, honeyPoints)

	//将假命令插入到适当的位置
	newLines := append(lines[:index], append(fakeCommands, lines[index:]...)...)

	//将更新后的内容写回文件
	if err := writeLines(filePath, newLines); err != nil {
		return fmt.Errorf("failed to write file: %w", err)
	}

	return nil
}

func generateFakeCommands(commandType CommandType, honeyPoints []string) []string {
	fakeCommands := []string{}

	for _, honeyPoint := range honeyPoints {
		switch commandType {
		case FileAccess:
			// 检查路径是否是文件或目录
			info, err := os.Stat(honeyPoint)
			if err != nil {
				// 如果路径无效，插入注释
				fakeCommands = append(fakeCommands, fmt.Sprintf("# Path not found: %s", honeyPoint))
				continue
			}

			// 根据路径类型选择模板
			var selectedTemplates []string
			if info.IsDir() {
				// 目录模板
				selectedTemplates = directoryTemplates
			} else {
				// 文件模板
				selectedTemplates = fileTemplates
			}

			// 随机选择模板并替换占位符
			template := getRandomTemplate(selectedTemplates)
			command := substituteTemplate(template, honeyPoint)
			fakeCommands = append(fakeCommands, command)

		case URLAccess:
			// 随机选择 URLAccess 的模板
			template := getRandomTemplate(urlAccessTemplates)
			command := substituteTemplate(template, honeyPoint)
			fakeCommands = append(fakeCommands, command)

		case SSHKey:
			// 随机选择 SSHKey 的模板
			template := getRandomTemplate(sshKeyTemplates)
			command := substituteTemplate(template, honeyPoint)
			fakeCommands = append(fakeCommands, command)

		default:
			// 未知类型，插入注释
			fakeCommands = append(fakeCommands, fmt.Sprintf("# Unknown command type with honey point: %s", honeyPoint))
		}
	}

	return fakeCommands
}

// getRandomFileFromDir从给定目录中随机选择一个文件。
func getRandomFileFromDir(dirPath string) string {
	files := []string{}

	// 遍历目录下的所有文件
	err := filepath.Walk(dirPath, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		// 只添加普通文件（排除目录等）
		if !info.IsDir() {
			files = append(files, info.Name()) // 仅收集文件名（相对路径）
		}
		return nil
	})
	if err != nil {
		return ""
	}

	// 如果没有可用文件，返回空字符串
	if len(files) == 0 {
		return ""
	}

	// 随机选择一个文件
	return files[rand.Intn(len(files))]
}

// writeLines一行行写回文件
func writeLines(filePath string, lines []string) error {
	file, err := os.Create(filePath)
	if err != nil {
		return fmt.Errorf("failed to create file: %w", err)
	}
	defer file.Close()

	writer := bufio.NewWriter(file)
	for _, line := range lines {
		_, err := writer.WriteString(line + "\n")
		if err != nil {
			return fmt.Errorf("failed to write line: %w", err)
		}
	}

	if err := writer.Flush(); err != nil {
		return fmt.Errorf("failed to flush writer: %w", err)
	}

	return nil
}

func substituteTemplate(template string, honeyPoint string) string {
	info, err := os.Stat(honeyPoint)
	if err != nil {
		// 如果路径无效，返回注释
		return fmt.Sprintf("# Invalid path: %s", honeyPoint)
	}

	if info.IsDir() {
		// 如果是目录，随机选择目录中的文件
		randomFile := getRandomFileFromDir(honeyPoint)
		template = strings.ReplaceAll(template, "{directory}", honeyPoint)
		if randomFile != "" {
			template = strings.ReplaceAll(template, "{file}", randomFile)
		} else {
			template = strings.ReplaceAll(template, "{file}", "# No files found")
		}
	} else {
		// 如果是文件，直接替换占位符
		template = strings.ReplaceAll(template, "{target}", honeyPoint)
		template = strings.ReplaceAll(template, "{directory}", filepath.Dir(honeyPoint))
		template = strings.ReplaceAll(template, "{file}", filepath.Base(honeyPoint))
	}

	return template
}

// getRandomTemplate从模板列表中随机选择一个模板。
func getRandomTemplate(templates []string) string {
	return templates[rand.Intn(len(templates))]
}

//func main() {
//	line := 3                         // 插入到第 3 行
//	isReverse := false                // 是否倒数插入
//	commandType := FileAccess // 伪造操作类型
//	honeyPoints := []string{"/home/yiyi/confidential", "/home/yiyi/股东信息.docx"}
//
//	// 插入命令
//	err := InsertCommands(line, isReverse, commandType, honeyPoints)
//	if err != nil {
//		fmt.Println("Error:", err)
//	} else {
//		fmt.Println("Commands inserted successfully!")
//	}
//}
