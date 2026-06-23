package handlers

import (
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"net/http"
	"server/internal/models"
	"server/pkg"
	"strconv"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/sirupsen/logrus"
)

func buildPublicTokenURL(token string) string {
	scheme := "http"
	if pkg.Cfg.EnableHTTPS {
		scheme = "https"
	}

	host := pkg.Cfg.Public_ip
	if host == "" {
		host = "127.0.0.1"
	}

	base := fmt.Sprintf("%s://%s", scheme, host)
	if pkg.Cfg.Public_port != "" {
		base = fmt.Sprintf("%s:%s", base, pkg.Cfg.Public_port)
	}

	token = strings.Trim(strings.TrimSpace(token), "/")
	if token == "" {
		return ""
	}
	return base + "/static/img/logo-" + token + ".png"
}

// API:服务器测试
func TestHandler(c *gin.Context) {
	c.JSON(200, gin.H{
		"message":    "service start...",
		"User-IP":    c.ClientIP(),
		"User-Agent": c.GetHeader("User-Agent"),
		"Time":       time.Now().Format("2006-01-02 15:04:05.000 Mon Jan"),
	})
}

// API:token生成数据
func IndexHandler(c *gin.Context) {
	c.HTML(http.StatusOK, "index.html", nil)
}

// API:token生成
func CreateTokenHandler(c *gin.Context) {
	var companyInfo models.CompanyInfo // 获取公司信息
	if info, exist := c.Get("companyInfo"); exist {
		companyInfo = info.(models.CompanyInfo) // 获取公司信息
	} else {
		c.JSON(http.StatusBadRequest, gin.H{
			"code":    1,
			"message": "company info not found",
			"data":    "",
		})
		return
	}

	type Token struct {
		MailAddr string `json:"mail_addr" form:"mail_addr" binding:"required"`
		AlertMsg string `json:"alert_msg" form:"alert_msg" binding:"required"`
	}
	var token Token
	if c.ContentType() == "application/json" { // json参数
		if err := c.ShouldBindJSON(&token); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()}) // 参数有误
			return
		}
	} else if c.ContentType() == "application/x-www-form-urlencoded" || c.ContentType() == "multipart/form-data" {
		// 绑定 POST 表单数据
		if err := c.ShouldBind(&token); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()}) // 参数有误
			return
		}
	} else {
		c.JSON(http.StatusUnsupportedMediaType, gin.H{"error": "Unsupported content type"})
		return
	}
	alert_addr := token.MailAddr
	alert_msg := token.AlertMsg

	hash := sha256.Sum256([]byte(alert_addr + alert_msg))
	hash_slice := make([]byte, len(hash)) // 创建切片
	copy(hash_slice, hash[:])
	tokenStr := base64.RawURLEncoding.EncodeToString(hash_slice)
	// token_url := "http://" + getPublicIp() + ":" + port + "/contact/" + tokenStr
	info := models.TokenInfo{
		Token:      tokenStr,
		Alert_addr: alert_addr,
		Alert_msg:  alert_msg,
		Company_id: companyInfo.Id,
	}

	errCode := models.InsertToken(pkg.Db, &info)
	if errCode != 0 {
		c.JSON(http.StatusOK, gin.H{
			"code":    1,
			"message": "msg is used",
			"data":    "",
		})
		return
	} else {
		token := buildPublicTokenURL(tokenStr)
		c.JSON(http.StatusOK, gin.H{
			"code":    0,
			"message": "Success",
			"token":   token,
		})
		return
	}

}

// API:查询token信息
func FindTokenHandler(c *gin.Context) {
	type Token struct {
		TokenStr string `json:"token" binding:"required"`
	}
	var token Token
	err := c.ShouldBindJSON(&token)
	if err != nil {
		fmt.Println(err)
		c.JSON(http.StatusOK, gin.H{
			"code":    1,
			"message": "参数错误",
			"data":    "",
		})
		return
	}
	tokenStr := token.TokenStr

	// 从上下文获取公司信息
	var companyInfo models.CompanyInfo // 获取公司信息
	if info, exist := c.Get("companyInfo"); exist {
		companyInfo = info.(models.CompanyInfo) // 获取公司信息
	} else {
		c.JSON(http.StatusBadRequest, gin.H{
			"code":    1,
			"message": "company info not found",
			"data":    "",
		})
		return
	}
	companyId := companyInfo.Id

	// 查询该公司的告警信息
	res, err := models.FindTokenInfo(pkg.Db, tokenStr, companyId)
	if err != nil {
		c.JSON(http.StatusOK, gin.H{
			"code":    1,
			"message": err.Error(),
			"data":    "",
		})
	} else {
		c.JSON(http.StatusOK, gin.H{
			"code":    0,
			"message": "success",
			"data":    res,
		})
	}

}

// API:获取告警日志
func GetTriggerLogHandler(c *gin.Context) {
	var err error
	var companyInfo models.CompanyInfo // 获取公司信息
	if info, exist := c.Get("companyInfo"); exist {
		companyInfo = info.(models.CompanyInfo) // 获取公司信息
	} else {
		c.JSON(http.StatusBadRequest, gin.H{
			"code":    1,
			"message": "company info not found",
			"data":    "",
		})
		return
	}

	var req_time time.Time                                   // 查询时间
	count, _ := strconv.Atoi(c.DefaultQuery("count", "100")) // 获取条数(默认100)
	time_format := c.Query("time_format")                    // 获取时间格式(timestamp/datetime)

	if time_format == "timestamp" { // 传入的时间格式为时间戳
		timeStampStr := c.Query("time") // 使用时间戳查询
		timeStamp, err := strconv.ParseInt(timeStampStr, 10, 64)
		if err != nil {
			c.JSON(200, gin.H{
				"code":    1,
				"message": "Invalid timestamp format",
				"data":    nil,
			})
			return
		}
		loc, err := time.LoadLocation("Asia/Shanghai") // 将 int64 类型的时间戳转换为 time.Time 类型
		if err != nil {
			logrus.Error("[ERROR]时间戳转换失败", err)
			c.JSON(200, gin.H{
				"code":    1,
				"message": "Time transfer error",
				"data":    nil,
			})
			return
		}
		req_time = time.Unix(timeStamp, 0).UTC().In(loc)
	} else { // 否则时间格式为时间字符串
		// 判断是否设置时间参数
		if timeStr := c.PostForm("time"); timeStr != "" {
			if timeStr[1] == '"' { // 判断是否有多余双引号
				timeStr = timeStr[1 : len(timeStr)-1] // 去除多余的双引号
			}
			req_time, err = time.Parse("2006-01-02 15:04:05", timeStr)
			if err != nil {
				logrus.Error("[ERROR]时间戳解析", err)
				c.JSON(200, gin.H{
					"code":    1,
					"message": "Time Parse error",
					"data":    nil,
				})
				return
			}
		} else {
			// 获取30天前的时间
			req_time = time.Now().AddDate(0, 0, -30)
		}
	}

	// 查公司对应的告警日志
	triggerInfos := models.FindTriggerLog(pkg.Db, count, req_time, companyInfo.Id)
	data := map[string]interface{}{
		"code":    0,
		"message": "success",
		"data": map[string]interface{}{
			"triggerInfos": triggerInfos,
			"total":        len(triggerInfos),
		},
	}
	c.JSON(200, data)
}
