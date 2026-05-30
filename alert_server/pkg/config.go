package pkg

import (
	"bufio"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"github.com/gin-gonic/gin"
	"github.com/go-ini/ini"
	"github.com/sirupsen/logrus"
)

const (
	ALERT_MODE_NONE      = 0 // 不发送邮件告警
	ALERT_MODE_STMPMAIL  = 1 // 使用SMTP发送邮件告警
	ALERT_MODE_CLOUDMAIL = 2 // 使用云邮件API发送邮件告警
)

type config struct {
	Public_ip         string                // 公网IP
	Public_port       string                // 公网端口
	Local_port        string                // 本地端口
	ServerMode        string                // 服务器模式
	EnableHTTPS       bool                  // 是否启用HTTPS
	EnableWhitelist   bool                  // 是否启用白名单模式
	AlertMode         int                   // 邮件模式
	AdminEmails       []string              // 管理员邮箱
	KeyValidateMode   int                   // api-key校验模式
	Api_key           string                // api-key
	EnableTriggerAuth bool                  // 是否启用触发接口认证
	TriggerAuthKey    string                // 触发接口认证密钥
	WhitelistFile     string                // 白名单文件
	BlocklistFile     string                // 黑名单文件
	Whitelist         map[string]*net.IPNet // 白名单
	Blocklist         map[string]*net.IPNet // 黑名单
	EnableLogColor    bool                  // 彩色日志开关
	Mu                *sync.Mutex
}

var (
	// cfgPath        = "config/config.ini" // 配置文件路径
	cfgFileContent *ini.File // 配置文件raw
	Cfg            *config   // 配置
)

// 加载黑名单文件
func loadConfigIpList(ipListPath string, list map[string]*net.IPNet, listName string) bool {
	file, err := os.Open(ipListPath)
	if err != nil {
		if os.IsNotExist(err) {
			// 文件不存在则创建一个新的block.list文件
			_, err = os.Create(ipListPath)
			if err != nil {
				return false
			}
			logrus.Infof("[Config] %s文件自动创建成功：%s", listName, ipListPath)
			return true
		} else {
			logrus.Errorf("[Config] %s文件加载出错,%s", listName, err)
			return false
		}
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") { // 如果存在空行或注释则跳过
			continue
		}
		_, ipnet, err := net.ParseCIDR(line)
		if err != nil {
			// 如果解析失败，可能是单个IP地址，手动添加/32前缀作为单个IP处理
			if ip := net.ParseIP(line); ip != nil {
				ipnet = &net.IPNet{
					IP:   ip,
					Mask: net.CIDRMask(32, 32),
				}
				list[ipnet.String()] = ipnet
			} else {
				logrus.Errorf("[Config] %s解析出错：%s", listName, err)
				continue
			}
		}
		list[ipnet.String()] = ipnet // 写入 list map
	}
	if err := scanner.Err(); err != nil {
		logrus.Errorf("[Config] %s文件读取出错,%s", listName, err)
		return false
	}
	// logrus.Info("[Config] 名单数量:", len(list))

	return true
}

// 从配置文件中加载public_ip和port
func loadConfigIPPort() bool {
	if cfgFileContent.Section("server").HasKey("public_ip") && cfgFileContent.Section("server").Key("public_ip").String() != "" {
		Cfg.Public_ip = cfgFileContent.Section("server").Key("public_ip").String()
	} else {
		logrus.Error("[Config] 配置缺失:public_ip")
		return false
	}
	if cfgFileContent.Section("server").HasKey("public_port") && cfgFileContent.Section("server").Key("public_port").String() != "" {
		Cfg.Public_port = cfgFileContent.Section("server").Key("public_port").String()
	} else {
		logrus.Warn("[Config] 配置缺失:public_port(默认端口:8080)")
		Cfg.Public_port = "8080" // 默认端口
	}
	if cfgFileContent.Section("server").HasKey("local_port") && cfgFileContent.Section("server").Key("local_port").String() != "" {
		Cfg.Local_port = cfgFileContent.Section("server").Key("local_port").String()
	} else {
		logrus.Warn("[Config] 配置缺失:local_port(默认端口:8080)")
		Cfg.Local_port = "8080" // 默认端口
	}
	return true
}

// 从配置文件中加载模式
func loadConfigMode() bool {
	if cfgFileContent.Section("server").HasKey("mode") && cfgFileContent.Section("server").Key("mode").String() != "" {
		Cfg.ServerMode = cfgFileContent.Section("server").Key("mode").String()
	} else {
		logrus.Warn("[Config] 配置缺失:未配置Server模式项mode(默认:release模式)")
		Cfg.ServerMode = "release"
	}
	return true
}

// 从配置文件中加载是否启用HTTPS
func loadConfigTlsMode() bool {
	if cfgFileContent.Section("server").HasKey("https") && cfgFileContent.Section("server").Key("https").String() != "" {
		Cfg.EnableHTTPS = cfgFileContent.Section("server").Key("https").String() == "true"
	} else {
		logrus.Error("[Config] 配置缺失:未配置HTTPS模式项https(默认:HTTP模式)")
	}
	return true
}

// 从配置文件中加载email模式
func loadConfigEmailMode() bool {
	if cfgFileContent.Section("alert").HasKey("mode") && cfgFileContent.Section("alert").Key("mode").String() != "" {
		mode := cfgFileContent.Section("alert").Key("mode").String()
		switch mode {
		case "1": // 使用SMTP发送邮件告警
			Cfg.AlertMode = ALERT_MODE_STMPMAIL
		case "2": // 使用云邮件API发送邮件告警
			Cfg.AlertMode = ALERT_MODE_CLOUDMAIL
		default:
			Cfg.AlertMode = ALERT_MODE_NONE
		}
	} else {
		logrus.Error("[Config] 配置缺失:未配置告警模式项alert.mode(默认:关闭邮箱告警)")
	}
	return true
}

// 从配置文件中加载email模式
func loadConfigAdminEmail() bool {
	if cfgFileContent.Section("alert").HasKey("admin_email") && cfgFileContent.Section("alert").Key("admin_email").String() != "" {
		// 获取并拆分邮箱列表
		emails := cfgFileContent.Section("alert").Key("admin_email").String()
		emailList := strings.Split(emails, ",")
		validEmails := []string{}

		// 去除每个邮箱前后的空格，并验证邮箱格式
		for _, email := range emailList {
			trimmedEmail := strings.TrimSpace(email)
			if IsValidEmail(trimmedEmail) {
				validEmails = append(validEmails, trimmedEmail)
			} else {
				logrus.Warnf("[Config] 无效的邮箱地址: %s", trimmedEmail)
			}
		}
		Cfg.AdminEmails = validEmails
	} else {
		logrus.Warn("[Config] 配置缺失:未配置管理员邮箱项alert.admin_mail(默认:空)")
	}
	return true
}

// 从配置文件中加载api-key校验模式
func loadConfigKeyValidateMode() bool {
	// var err error
	// Cfg.KeyValidateMode, err = cfgFileContent.Section("server").Key("key_mode").Int()
	// if err != nil {
	// 	logrus.Printf("[Config] 配置错误:api-key配置有误(默认:模式1-配置文件校验)")
	// 	Cfg.KeyValidateMode = 1
	// }
	Cfg.Api_key = cfgFileContent.Section("server").Key("api-key").String()
	// 检查 api-key 是否存在且不为空
	if Cfg.Api_key == "" {
		logrus.Println("[Config] 配置缺失:未配置api-key项")
		return false
	}
	return true
}

// 加载触发auth配置
func loadConfigTriggerAuth() bool {
	if cfgFileContent.Section("server").HasKey("trigger_auth") && cfgFileContent.Section("server").Key("trigger_auth").String() != "" {
		Cfg.EnableTriggerAuth = cfgFileContent.Section("server").Key("trigger_auth").String() == "true"
		if Cfg.EnableTriggerAuth {
			Cfg.TriggerAuthKey = cfgFileContent.Section("server").Key("trigger_auth_key").String()
			if Cfg.TriggerAuthKey == "" {
				logrus.Error("[Config] 配置缺失:未配置触发auth密钥项trigger_auth_key")
				return false
			}
			logrus.Infof("[Config] 触发认证已启用，密钥为: %s", Cfg.TriggerAuthKey)
		}
	} else {
		logrus.Warn("[Config] 配置缺失:未配置触发认证模式项trigger_auth(默认:关闭)")
		Cfg.EnableTriggerAuth = false
	}
	return true
}

// 加载配置文件
func load() bool {
	if !loadConfigIPPort() || !loadConfigMode() ||
		!loadConfigTlsMode() || !loadConfigEmailMode() ||
		!loadConfigAdminEmail() || !loadConfigKeyValidateMode() ||
		!loadConfigTriggerAuth() ||
		!loadConfigIpList(Cfg.WhitelistFile, Cfg.Whitelist, "白名单") ||
		!loadConfigIpList(Cfg.BlocklistFile, Cfg.Blocklist, "黑名单") {
		logrus.Error("[Config] 以上配置文件存在缺失，请检查配置文件")
		return false
	}
	logrus.Info("   ├─ 服务器模式：   ", Cfg.ServerMode)
	logrus.Info("   ├─ 服务器公网IP:  ", Cfg.Public_ip)
	logrus.Info("   ├─ 服务器公网端口:", Cfg.Public_port)
	logrus.Info("   ├─ 服务器本地端口:", Cfg.Local_port)
	logrus.Info("   ├─ HTTPS模式:     ", Cfg.EnableHTTPS)
	logrus.Info("   ├─ 邮件告警模式:  ", Cfg.AlertMode)
	logrus.Info("   ├─ key验证模式:   ", Cfg.KeyValidateMode)
	logrus.Info("   ├─ 触发认证模式:   ", Cfg.EnableTriggerAuth)
	logrus.Info("   ├─ 触发认证密钥: ", Cfg.TriggerAuthKey)
	logrus.Info("   ├─ 白名单模式:    ", Cfg.EnableWhitelist)
	logrus.Info("   ├─ 白名单IP数量:  ", len(Cfg.Whitelist))
	logrus.Info("   └─ 黑名单IP数量:  ", len(Cfg.Blocklist))
	return true
}

// 加载配置文件
func LoadConfig() error {
	var err error

	// 加载项目所需路径
	err = InitProjectDir()
	if err != nil {
		logrus.Errorf("[Config] 加载路径失败: %v\n", err)
		return err
	}

	// 初始化Cfg
	Cfg = &config{
		WhitelistFile:  filepath.Join(ProjectRootDir, "config/ip_white.list"),
		BlocklistFile:  filepath.Join(ProjectRootDir, "config/ip_block.list"),
		Whitelist:      make(map[string]*net.IPNet),
		Blocklist:      make(map[string]*net.IPNet),
		EnableLogColor: false,
		Mu:             &sync.Mutex{},
	}

	// 读取配置文件
	cfgFilePath := filepath.Join(ProjectRootDir, "config/config.ini")
	cfgFileContent, err = ini.Load(cfgFilePath)
	if err != nil {
		logrus.Errorf("[Config] 加载配置文件失败: %v\n", err)
		return err
	}

	if !load() { // 加载配置文件
		return err
	}

	// 模式设置
	if Cfg.ServerMode == "release" {
		gin.SetMode(gin.ReleaseMode) // 设置为发布模式
	} else {
		gin.SetMode(gin.DebugMode) // 设置为Debug模式
	}

	return nil
}
