package main

import (
	"crypto/tls"
	"fmt"
	"net"
	"net/http"
	"server/internal/handlers"
	"server/internal/routes"
	"server/pkg"

	"github.com/gin-gonic/gin"
	"github.com/sirupsen/logrus"
	"github.com/soheilhy/cmux"
)

// ServerConfig 服务器配置结构
type ServerConfig struct {
	Router    http.Handler
	Port      string
	TLSConfig *tls.Config
	Name      string // 用于日志标识
}

func showBanner() {
	banner := `
═════════════════════════════════════════════════════════════
                  d8888  888b     d888 
                 d8P888  8888b   d8888 
                d8P 888  88888b.d88888 
               d8P  888  888Y88888P888 
              d88   888  888 Y888P 888 
              8888888888 888  Y8P  888 
                    888  888   "   888 
                    888  888       888 

    `
	fmt.Println(banner)
}

// StartServer 启动单个服务器（包含HTTP和HTTPS）
func StartServer(config ServerConfig) error {
	// 创建基础TCP监听器
	listener, err := net.Listen("tcp", ":"+config.Port)
	if err != nil {
		return fmt.Errorf("failed to create listener for %s: %v", config.Name, err)
	}

	// 创建cmux
	m := cmux.New(listener)

	// 创建TLS和HTTP监听器
	tlsListener := m.Match(cmux.TLS())
	httpListener := m.Match(cmux.Any())

	// 创建HTTPS服务器
	tlsServer := &http.Server{
		Handler:   config.Router,
		TLSConfig: config.TLSConfig,
	}

	// 创建HTTP服务器
	httpServer := &http.Server{
		Handler: config.Router,
	}

	// 启动HTTPS服务器
	go func() {
		if err := tlsServer.Serve(tls.NewListener(tlsListener, config.TLSConfig)); err != nil {
			logrus.Errorf("%s HTTPS server error: %v", config.Name, err)
		}
	}()

	// 启动HTTP服务器
	go func() {
		if err := httpServer.Serve(httpListener); err != nil {
			logrus.Errorf("%s HTTP server error: %v", config.Name, err)
		}
	}()

	// 启动cmux
	go func() {
		if err := m.Serve(); err != nil {
			logrus.Errorf("%s cmux error: %v", config.Name, err)
		}
	}()

	return nil
}

func main() {
	showBanner()
	// 加载日志记录器
	pkg.SetupLogger()
	logrus.Info("================系统加载================")

	// 加载配置文件
	var err error
	logrus.Info("[1] 正在加载配置文件...")
	err = pkg.LoadConfig()
	if err != nil {
		return
	}

	// 加载数据库
	logrus.Info("[2] 正在加载数据库...")
	db, err := pkg.InitDB()
	if err != nil {
		logrus.Error("数据库初始化失败")
		return
	}

	// 初始化寄生蜜点处理器
	logrus.Info("[2.5] 正在初始化寄生蜜点处理器...")
	handlers.InitParasiticHandlers(db)

	// 注册路由和中间件
	logrus.Info("[3] 正在注册路由和中间件...")
	adminRouter := gin.New()
	alertRouter := gin.New()

	routes.AdminRoutes(adminRouter)
	routes.BusinessRoutes(alertRouter)
	routes.ParasiticRoutes(alertRouter) // 寄生蜜点路由

	// 加载模板
	logrus.Info("[4] 正在加载模板...")
	adminRouter.LoadHTMLGlob("templates/*")
	alertRouter.LoadHTMLGlob("templates/*")

	logrus.Info("================加载完成================")
	logrus.Info("系统正在启动...")

	// 创建监听器，一个端口同时支持http和https请求
	// listener -> cmux	->
	// 						-> httplistener -> httpServer
	// 						-> tlslistener -> httpsServer
	cert, err := pkg.LoadCert()
	if err != nil {
		logrus.Error(err)
	}
	tlsConfig := pkg.LoadTlsConfig(*cert)

	// 启动告警服务器
	alertConfig := ServerConfig{
		Router:    alertRouter,
		Port:      pkg.Cfg.Public_port,
		TLSConfig: tlsConfig,
		Name:      "Alert",
	}
	if err := StartServer(alertConfig); err != nil {
		logrus.Fatal(err)
	}

	// 启动管理服务器
	adminConfig := ServerConfig{
		Router:    adminRouter,
		Port:      pkg.Cfg.Local_port,
		TLSConfig: tlsConfig,
		Name:      "Admin",
	}
	if err := StartServer(adminConfig); err != nil {
		logrus.Fatal(err)
	}
	logrus.Info("启动成功！")
	// 使用 channel 保持主程序运行
	select {}
}
