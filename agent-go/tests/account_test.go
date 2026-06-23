// finalshell_config_test.go
package tests

// import (
// 	"testing"

// 	"systemwire/agent/internal/account"
// 	"systemwire/agent/internal/models"
// )

// func TestAccount(t *testing.T) {
// 	// 创建一个临时目录

// 	accounter := account.NewAccountDeployer()
// 	shellCfg := &models.ShellCfg{
// 		Username: "test123",
// 		Password: "dsadsadsadsa",
// 		Host:     "192.168.3.105",
// 		Port:     22022,sshell/Sessions",	// xshell config path
// Path: "F:/finalshell/conn", // finalshell config path
//}

// // 生成xshell配置文件
// path, err := accounter.GetXshellDefaultPath()
// if err != nil {
// 	fmt.Println(err)
// 	return
// }
// shellCfg.Path = path
// accounter.DeployXshellConfig(*shellCfg)

// shellCfg.Path = accounter.GetSectionKeyString("Finalshell")
// accounter.DeployFinalshellConfig(*shellCfg)

// vpnIp := "123.123.123.123"
// port := 1194
// vpnConfigPath := "C:/Users/Teri/OpenVPN/config"
// // 生成openvpn配置
// accounter.DeployVPNConfig(vpnIp, port, vpnConfigPath)

//};
