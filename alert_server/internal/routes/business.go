package routes

import (
	"net/http"
	"net/url"
	"server/internal/handlers"
	"server/internal/middlewares"
	"server/pkg"
	"strings"
	"time"

	"github.com/gin-contrib/cors"
	"github.com/gin-gonic/gin"
)

func BusinessRoutes(router *gin.Engine) {
	config := cors.DefaultConfig()
	config.AllowOriginFunc = func(origin string) bool {
		origin = strings.TrimSpace(strings.ToLower(origin))
		if origin == "" || origin == "null" || origin == "file://" {
			return true
		}

		parsed, err := url.Parse(origin)
		if err != nil {
			return false
		}

		host := strings.ToLower(parsed.Hostname())
		switch host {
		case "localhost", "127.0.0.1", "::1":
			return true
		default:
			return false
		}
	}
	config.AllowMethods = []string{"POST", "GET", "OPTIONS"}
	config.AllowHeaders = []string{"Content-Type", "Access-Control-Allow-Headers", "Authorization", "X-Requested-With"}
	config.AllowCredentials = true
	config.MaxAge = 86400 * time.Second

	router.Use(middlewares.CustomRecoveryMiddleware())
	router.Use(middlewares.CustomLoggerMiddleware())
	router.Use(func(c *gin.Context) {
		applyParasiticPreflightHeaders(c)
		c.Next()
		applyParasiticPreflightHeaders(c)
	})
	router.Use(cors.New(config))
	router.Use(middlewares.SuspiciousURLMiddleware())

	if pkg.Cfg.EnableTriggerAuth {
		router.GET("/static/img/*token", middlewares.TriggerAuthMiddleware(), handlers.TriggerHandler)
		router.GET("/contact/*token", middlewares.TriggerAuthMiddleware(), handlers.TriggerHandler)
	} else {
		router.GET("/static/img/*token", handlers.TriggerHandler)
		router.GET("/contact/*token", handlers.TriggerHandler)
	}

	router.POST("/fingerprint", handlers.FingerprintHandle)
	router.POST("/account/alert", handlers.AccountAlertHandler)
	router.GET("/api/account-alerts", handlers.AccountAlertsHandler)
}

func applyParasiticPreflightHeaders(c *gin.Context) {
	if origin := c.GetHeader("Origin"); origin != "" {
		c.Header("Access-Control-Allow-Origin", origin)
	}
	c.Header("Vary", "Origin, Access-Control-Request-Method, Access-Control-Request-Headers, Access-Control-Request-Private-Network")

	if strings.EqualFold(c.GetHeader("Access-Control-Request-Private-Network"), "true") {
		c.Header("Access-Control-Allow-Private-Network", "true")
	}

	if c.Request.Method != http.MethodOptions {
		return
	}

	if requestHeaders := c.GetHeader("Access-Control-Request-Headers"); requestHeaders != "" {
		c.Header("Access-Control-Allow-Headers", requestHeaders)
	}
	if requestMethod := c.GetHeader("Access-Control-Request-Method"); requestMethod != "" {
		c.Header("Access-Control-Allow-Methods", requestMethod+", OPTIONS")
	}
}
