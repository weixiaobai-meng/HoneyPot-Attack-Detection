package routes

import (
	"server/internal/handlers"

	"github.com/gin-gonic/gin"
)

// ParasiticRoutes 注册寄生蜜点相关路由
// 注意：CORS 已在 BusinessRoutes 中配置，此处不再重复添加
func ParasiticRoutes(router *gin.Engine) {
	// 寄生蜜点接口（不需要 AdminAuth 鉴权，JS 直接在浏览器中调用）
	router.POST("/cdn/security/verify", handlers.RequestTypeMiddleware(), handlers.BotCheckHandler)
	router.POST("/cdn/security/verify/", handlers.RequestTypeMiddleware(), handlers.BotCheckHandler)
	router.POST("/cdn/analytics", handlers.FingerprintInfoHandler)
	router.POST("/cdn/analytics/", handlers.FingerprintInfoHandler)
	router.POST("/cdn/analytics/geo", handlers.IPSHandler)
	router.POST("/cdn/analytics/geo/", handlers.IPSHandler)
	router.GET("/socket", handlers.WSHandler)
	router.GET("/socket/", handlers.WSHandler)
	router.GET("/api/pixel", handlers.PixelHandler)
}
