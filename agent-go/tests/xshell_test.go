// xshell_config_test.go
package tests

import (
	"testing"
)

func TestXshellConfig_GenerateConfig(t *testing.T) {
	// // 创建一个临时目录
	// tempDir := t.TempDir()

	// // 创建 XshellConfig 实例
	// xConfig := &XshellConfig{
	// 	Host:     "127.0.0.1",
	// 	Port:     22,
	// 	Username: "testuser",
	// }

	// // 生成配置
	// err := xConfig.generateConfig(xConfig.Username, xConfig.Host, xConfig.Port, tempDir)
	// assert.NoError(t, err, "Xshell config generation failed")

	// // 检查生成的配置文件是否存在
	// filePath := tempDir + "/Fakexshell.xsh"
	// _, err = os.Stat(filePath)
	// assert.NoError(t, err, "Xshell config file not created")

	// // 清理生成的文件（如果需要）
	// os.Remove(filePath)
}
