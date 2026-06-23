package routes

import (
	"server/internal/handlers"
	"server/internal/middlewares"
	"server/pkg"

	"github.com/gin-gonic/gin"
)

// 注册管理路由、使用中间件
func AdminRoutes(router *gin.Engine) {
	// 黑白名单过滤器
	filter := pkg.NewFileter(pkg.Cfg.Whitelist, pkg.Cfg.Blocklist)

	// 使用中间件
	router.Use(middlewares.CustomRecoveryMiddleware())          // 自定义恢复中间件
	router.Use(middlewares.CustomLoggerMiddleware())            // 日志中间件
	router.SetTrustedProxies([]string{"127.0.0.1"})             // 信任的代理IP
	router.Use(middlewares.BlocklistMiddleware(pkg.Db, filter)) // 黑名单中间件
	router.Use(middlewares.SuspiciousURLMiddleware())           // 可疑请求中间件
	router.Use(middlewares.RateLimitMiddleware(filter))         // 限流中间件
	router.Use(middlewares.WhitelistMiddleware(filter))         // 白名单中间件
	router.Use(middlewares.AdminAuthMiddleware())               // 鉴权

	// 注册路由
	router.GET("/index", handlers.IndexHandler)              // 首页
	router.GET("/token/find", handlers.FindTokenHandler)     // 查找token
	router.POST("/token", handlers.CreateTokenHandler)       // 创建token
	router.GET("/alert/file", handlers.GetTriggerLogHandler) // 获取告警日志
	// router.GET("/alert/safe", handlers.GetSafeLogHandler)

	// 公司
	router.GET("/companys", handlers.FindCompanyAllHandler)         // 查找所有公司
	router.GET("/companys/:id", handlers.FindCompanyByIdHandler)    // 查找id对应公司
	router.POST("/companys", handlers.CreateCompanyHandler)         // 添加公司
	router.POST("/companys/:id", handlers.UpdateCompanyHandler)     // 修改公司信息
	router.DELETE("/companys/:name", handlers.DeleteCompanyHandler) // 删除公司

	// 过滤器
	router.GET("/filters/white", handlers.FindFilterWhiteListHandler) // 查找白名单
	router.POST("/filters/white", handlers.CreateFilterWhite)         // 添加白名单
	router.DELETE("/filters/white", handlers.DeleteFilterWhite)       // 删除白名单

	// 寄生蜜点数据查询（需要鉴权）
	router.GET("/api/logs", handlers.LogsHandler)
	router.GET("/internal/target-ips", handlers.TargetIPsHandler)

}
