// finalshell_config_test.go
package tests

import (
	"testing"
)

func TestFinalshellConfig_GenerateConfig(t *testing.T) {
	// // 创建一个临时目录
	// tempDir := t.TempDir()

	// // 创建 FinalshellConfig 实例
	// fConfig := &account.FinalshellConfig{
	// 	UserName: "testuser",
	// 	Host:     "127.0.0.1",
	// 	Port:     22,
	// 	Path:     "D:\\test", // 配置文件保存路径
	// }

	// // 生成配置
	// err := fConfig.generateConfig(fConfig.UserName, fConfig.Host, fConfig.Port, tempDir)
	// assert.NoError(t, err, "FinalShell config generation failed")

	// // 检查生成的配置文件是否存在
	// filePath := tempDir + "/" + fConfig.ID + "_finalshell_config.txt"
	// _, err = os.Stat(filePath)
	// assert.NoError(t, err, "FinalShell config file not created")

}
