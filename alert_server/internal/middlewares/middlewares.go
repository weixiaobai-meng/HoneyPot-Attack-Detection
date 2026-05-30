package middlewares

import (
	"fmt"
	"net/http"
	"os"
	"regexp"
	"runtime/debug"
	"server/internal/models"
	"server/pkg"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/sirupsen/logrus"
	"gorm.io/gorm"
)

// admin鉴权
func AdminAuthMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		// 拿出api-key
		auth := c.GetHeader("Authorization")
		if auth == "" {
			logrus.Warn("[警告] 未授权访问，未提供Authorization头")
			c.AbortWithStatus(http.StatusUnauthorized)
			return
		}
		if strings.HasPrefix(auth, "Bearer ") {
			auth = strings.TrimPrefix(auth, "Bearer ")
			auth = strings.TrimSpace(auth)
		}

		var companyInfo models.CompanyInfo

		// 校验api-key
		companyInfo, err := isValidToken(auth)
		if err != nil {
			logrus.Warn("[警告] 鉴权失败:", err)
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "access denied"})
			return
		}

		// 将公司信息存储在上下文中
		c.Set("companyInfo", companyInfo)
		logrus.Infof("[鉴权] 鉴权成功, ID:%d, 描述:%s, 角色:%s", companyInfo.Id, companyInfo.Description, companyInfo.Role)

		// 对 /companys 开头的请求强制要求 admin 角色
		if strings.HasPrefix(c.Request.URL.Path, "/companys") && companyInfo.Role != "admin" {
			c.AbortWithStatusJSON(http.StatusForbidden, gin.H{"error": "access denied"})
			return
		}

		c.Next()
	}
}

// 绊线接口鉴权
func TriggerAuthMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		// 打印所有请求头，方便调试
		for k, v := range c.Request.Header {
			logrus.Infof("Header: %s=%v", k, v)
		}
		// 鉴权逻辑
		ip := c.GetHeader("Client-IP")
		auth := c.GetHeader("Authorization")
		if auth == "" {
			logrus.Warnf("[警告] IP:%v, 未授权访问，未提供Authorization头", ip)
			c.AbortWithStatus(http.StatusNotFound)
			return
		}
		logrus.Infof("请求来自 IP: %s", ip)

		// 从配置文件中获取API密钥
		if auth != pkg.Cfg.TriggerAuthKey {
			logrus.Warnf("[警告] IP:%v, 鉴权失败: API密钥不匹配", ip)
			c.AbortWithStatus(http.StatusUnauthorized)
			return
		}
		//token := c.Param("token")[1:]
		token := c.Param("token")
		if token == "" {
			logrus.Warnf("[警告] IP:%v, 未提供token", ip)
			c.AbortWithStatus(http.StatusUnauthorized)
			return
		}
		c.Set("token", token) // 将token存储在上下文中
		c.Set("clientIp", ip) // 将IP存储在上下文中
		logrus.Infof("[鉴权] 鉴权成功,IP:%v,token:%s", ip, token)

		c.Next()
	}
}

func isValidToken(token string) (models.CompanyInfo, error) {
	// 格式校验：必须只能是字母和数字
	reg := `^[a-zA-Z0-9]+$`
	matched, err := regexp.MatchString(reg, token)
	if err != nil {
		return models.CompanyInfo{}, fmt.Errorf("正则表达式匹配错误: %v", err)
	} else if !matched {
		return models.CompanyInfo{}, fmt.Errorf("token格式不合法: %s", token)
	}
	// 是否与配置文件中的api-key一致，一致则为超级管理员
	if token == pkg.Cfg.Api_key {
		return models.CompanyInfo{Id: 0, Role: "admin"}, nil // 超级管理员
	}
	// 查数据库验证是否存在
	res, err := models.FindCompanyInfoByKey(pkg.Db, token)
	if err != nil {
		return models.CompanyInfo{}, fmt.Errorf("token校验失败: %v", err)
	}
	return models.CompanyInfo{
		Model:       gorm.Model{},
		Id:          res.Id,
		ApiKey:      res.ApiKey,
		Description: res.Description,
		Role:        res.Role,
	}, nil
}

// 限流中间件，检查当前请求是否超过限制
func RateLimitMiddleware(filter *pkg.Filter) gin.HandlerFunc {
	go filter.CleanupVisitors()

	return func(c *gin.Context) {
		ip := c.ClientIP()
		visitor := filter.GetVisitor(ip)

		if pkg.IsInIPlist(ip, filter.GetBlockList()) || !visitor.Limiter.Allow() {
			visitor.Attempts++
			if visitor.Attempts > 10 { // 超过10次请求失败则加入黑名单
				filter.AddToBlockIP(ip)
			}
			c.AbortWithStatus(http.StatusNotFound)
			return
		}

		visitor.Attempts = 0
		c.Next()
	}
}

// IP 白名单中间件
func WhitelistMiddleware(filter *pkg.Filter) gin.HandlerFunc {
	if pkg.Cfg.EnableWhitelist {
		return func(c *gin.Context) {
			ip := c.ClientIP()
			requestURL := c.Request.URL.String()
			// 检查是否为本机或白名单
			if ip != "127.0.0.1" && ip != "::1" && !pkg.IsInIPlist(ip, filter.GetWhiteList()) {
				// c.HTML(http.StatusNotFound, "404.html", nil)
				c.AbortWithStatus(http.StatusNotFound)
				logrus.Warn("[警告] 非白名单访问警告，IP\t", ip, "\tURL:", requestURL)
				sec_log := models.SecurityLog{
					Trigger_time: time.Now(),
					Src_ip:       ip,
					Event:        "whitelist",
					Url:          requestURL,
				}

				// 记录到数据库中
				go func(db *gorm.DB, sec_log *models.SecurityLog) {
					models.Insert_securityLog(db, sec_log)
				}(pkg.Db, &sec_log)

				return
			}
			c.Next()
		}
	} else {
		return func(c *gin.Context) {
			c.Next()
		}
	}
}

// 黑名单中间件
func BlocklistMiddleware(db *gorm.DB, filter *pkg.Filter) gin.HandlerFunc {
	return func(c *gin.Context) {
		ip := c.ClientIP()
		requestURL := c.Request.URL.String()
		if pkg.IsInIPlist(ip, filter.GetBlockList()) {
			// c.AbortWithStatus(http.StatusForbidden)
			c.AbortWithStatus(http.StatusNotFound)
			logrus.Warn("[Blocklist] 拦截请求 ,", ip, " ,", requestURL)
			sec_log := models.SecurityLog{
				Trigger_time: time.Now(),
				Src_ip:       ip,
				Event:        "blocklist",
				Url:          requestURL,
			}

			// 记录到数据库中
			go func(db *gorm.DB, sec_log *models.SecurityLog) {
				models.Insert_securityLog(db, sec_log)
			}(db, &sec_log)
			return
		}
		c.Next()
	}
}

// 可疑URL访问记录中间件
func SuspiciousURLMiddleware() gin.HandlerFunc {
	// 预期的接口路径列表
	expectedPaths := map[string]bool{
		"/test/2024":      true,
		"/index":          true,
		"/token":          true,
		"/get_triggerLog": true,
		"/config/reload/": true,
		"/favicon.ico":    true,
		// "/contact":        true,
	}
	return func(c *gin.Context) {
		path := c.Request.URL.Path
		if !expectedPaths[path] { // 请求的URL不在合法URL名单中
			if strings.HasPrefix(path, "/contact") { // 是不是请求了以/contact为前缀的URL
				c.Next()
			} else { // 非法的URL请求
				clientIP := c.ClientIP()
				method := c.Request.Method
				rawQuery := c.Request.URL.RawQuery

				suspiciousInfo := fmt.Sprintf("IP: %s ,URL: %s ,Method: %s ,Query: %s\n",
					clientIP, path, method, rawQuery)

				// 将可疑信息记录到文件
				file, err := os.OpenFile("log/ip_suspicious.log", os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
				if err != nil {
					logrus.Errorf("无法打开可疑日志文件: %v", err)
				} else {
					defer file.Close()
					if _, err := file.WriteString(suspiciousInfo); err != nil {
						logrus.Errorf("无法写入可疑日志文件: %v", err)
					}
				}
			}
		}
		c.Next()
	}
}

// 自定义恢复中间件
func CustomRecoveryMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		defer func() {
			if err := recover(); err != nil {
				logrus.Errorf("panic: %+v", err)
				logrus.Printf("%s", debug.Stack())
				c.AbortWithStatus(500)
			}
		}()
		c.Next()
	}
}

const (
	green     = "\033[32m"
	yellow    = "\033[33m"
	red       = "\033[31m"
	blue      = "\033[34m"
	cyan      = "\033[36m"
	brightRed = "\033[91m"
	reset     = "\033[0m"
)

// 日志中间件（优化版）
func CustomLoggerMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		start := time.Now()
		raw := c.Request.URL.RawQuery
		c.Next()

		end := time.Now()
		latency := end.Sub(start)
		status := c.Writer.Status()
		method := c.Request.Method
		clientIP := c.ClientIP()
		path := c.Request.URL.Path
		if raw != "" {
			path += "?" + raw
		}

		// 状态颜色
		color := reset
		switch {
		case status >= 200 && status < 300:
			color = green
		case status >= 300 && status < 400:
			color = blue
		case status >= 400 && status < 500:
			color = yellow
		case status >= 500:
			color = brightRed
		}

		// 方法颜色（可选）
		methodColor := cyan
		switch method {
		case "GET":
			methodColor = blue
		case "POST":
			methodColor = green
		case "PUT":
			methodColor = yellow
		case "DELETE":
			methodColor = red
		}

		fmt.Fprintf(gin.DefaultWriter,
			"%s[GIN] %s |%s %3d %s| %-12v | %15s |%s %-6s %s| %s\n",
			reset,
			end.Format("2006/01/02 15:04:05"),
			color, status, reset,
			latency,
			clientIP,
			methodColor, method, reset,
			path,
		)
	}
}
