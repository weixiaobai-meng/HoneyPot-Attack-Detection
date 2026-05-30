package routes

import (
	"server/internal/handlers"
	"server/internal/middlewares"
	"server/pkg"
	"time"

	"github.com/gin-contrib/cors"
	"github.com/gin-gonic/gin"
)

func BusinessRoutes(router *gin.Engine) {
	// CORS 配置
	config := cors.DefaultConfig()
	config.AllowAllOrigins = true
	config.AllowMethods = []string{"POST", "GET", "OPTIONS", "PUT", "DELETE"}
	config.AllowHeaders = []string{"Content-Type", "Access-Control-Allow-Headers", "Authorization", "X-Requested-With"}
	config.AllowCredentials = true
	config.MaxAge = 86400 * time.Second

	// 中间件
	router.Use(middlewares.CustomRecoveryMiddleware()) // 自定义恢复中间件
	router.Use(middlewares.CustomLoggerMiddleware())   // 自定义日志中间件
	router.Use(cors.New(config))                       // 跨站中间件
	router.Use(middlewares.SuspiciousURLMiddleware())  // 可疑请求中间件
	if pkg.Cfg.EnableTriggerAuth {
		router.Use(middlewares.TriggerAuthMiddleware()) // 触发认证中间件
	}
	// 路由
	router.GET("/test/2024", handlers.TestHandler)          // 测试接口
	router.GET("/contact/*token", handlers.TriggerHandler)  // 文件告警触发接口
	router.POST("/fingerprint", handlers.FingerprintHandle) // 寄生蜜点js告警触发接口
}
