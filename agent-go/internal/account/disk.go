package account

import (
	"bytes"
	"os/exec"
	"strings"
)

// 获取磁盘列表
func GetDriveList() ([]string, error) {
	var drives []string
	// 使用Windows命令获取所有磁盘驱动器
	cmd := exec.Command("wmic", "logicaldisk", "get", "deviceid")
	var out bytes.Buffer
	cmd.Stdout = &out
	err := cmd.Run()
	if err != nil {
		return nil, err
	}

	// 解析命令输出并提取盘符
	output := out.String()
	lines := strings.Split(output, "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if len(line) > 0 && line[1] == ':' {
			drives = append(drives, line)
		}
	}
	return drives, nil
}
