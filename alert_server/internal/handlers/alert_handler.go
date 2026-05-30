package handlers

import (
	"encoding/json"
	"errors"
	"net/http"
	"os"
	"server/internal/models"
	"server/pkg"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/sirupsen/logrus"
	"gorm.io/gorm"
)

const (
	ALERT_MODE_NONE      = 0 // 不发送邮件告警
	ALERT_MODE_STMPMAIL  = 1 // 使用SMTP发送邮件告警
	ALERT_MODE_CLOUDMAIL = 2 // 使用云邮件API发送邮件告警
)

var eventLogger = logrus.New() // 用于记录告警事件的日志
// 告警触发
func TriggerHandler(c *gin.Context) {
	eventLogfd, err := os.OpenFile("log/event.log", os.O_RDWR|os.O_CREATE|os.O_APPEND, 0666)
	if err != nil {
		logrus.Fatal("open file error")
	}

	// 设置日志输出到文件和标准输出
	eventLogger.SetOutput(eventLogfd)
	// 取token的值
	var token string
	if t, exist := c.Get("token"); exist {
		token = t.(string)
	} else {
		token = c.Param("token")[1:]
	}

	go func() { // 异步处理告警
		var srcIP string
		if ip, exits := c.Get("clientIp"); exits {
			srcIP = ip.(string) // 获取源IP
			// fmt.Println("clientIp:", srcIP)
		} else {
			// srcIP = c.ClientIP() //获取源IP
			srcIP = c.GetHeader("X-Forwarded-For") // 获取源IP，优先使用X-Forwarded-For头
			// fmt.Println("X-Forwarded-For:", srcIP)
		}

		requestURL := c.Request.URL.String() //获取请求的Url
		// 防止sql注入
		if strings.Contains(token, "'") {
			logrus.Warn("[警告] 疑似sql注入,IP:", srcIP)
			sec_log := models.SecurityLog{
				Trigger_time: time.Now(),
				Src_ip:       srcIP,
				Event:        "sql注入",
				Url:          requestURL,
			}
			models.Insert_securityLog(pkg.Db, &sec_log)
			return
		}
		//查找邮件地址和告警信息
		tokenInfo, err := models.FindAlertMsg(pkg.Db, token)
		if errors.Is(err, gorm.ErrRecordNotFound) {
			// token不存在
			logrus.Warn("[警告] 疑似路径爆破,", srcIP, ",", requestURL)
			sec_log := models.SecurityLog{
				Trigger_time: time.Now(),
				Src_ip:       srcIP,
				Event:        "url爆破",
				Url:          requestURL,
			}
			models.Insert_securityLog(pkg.Db, &sec_log)
			return
		} else if err != nil {
			logrus.Error("[错误] 查找token信息失败:", err)
			return
		}

		eventLogger.SetFormatter(&logrus.JSONFormatter{
			TimestampFormat: "2006-01-02 15:04:05",
		})
		eventLog := eventLogger.WithFields(logrus.Fields{
			"message":    tokenInfo.Alert_msg, // 告警信息
			"token":      token,
			"trigger_ip": srcIP,
			"ip":         srcIP,
			"User-Agent": c.GetHeader("User-Agent"),
		})

		logrus.Info("[告警]: 文件触发告警 \t,ip:", srcIP, "\t,message:", tokenInfo.Alert_msg)
		//告警日志插入数据库
		var token_url string
		if pkg.Cfg.EnableHTTPS {
			token_url = "https://" + pkg.Cfg.Public_ip + ":" + pkg.Cfg.Public_port + "/contact/" + token
		} else {
			token_url = "http://" + pkg.Cfg.Public_ip + ":" + pkg.Cfg.Public_port + "/contact/" + token
		}

		loc, err := time.LoadLocation("Asia/Shanghai")
		if err != nil {
			logrus.Error("时间获取出错", err)
			return
		}
		triggerTime := time.Now().UTC().In(loc)

		triggerInfo := models.TriggerInfo{
			Token:         token,
			Token_url:     token_url,
			Trigger_time:  triggerTime,
			Trigger_ip:    c.ClientIP(),
			Alert_addr:    tokenInfo.Alert_addr,
			Alert_msg:     tokenInfo.Alert_msg,
			Trigger_agent: c.GetHeader("User-Agent"),
		}
		ret := models.Insert_trigger(pkg.Db, &triggerInfo)
		// sendAlertLog("http://172.25.0.100:18769/systemwire/file/receive_alert",

		// 	&triggerInfo)   #推送告警日志
		if ret != 0 {
			eventLog.Warn("文件告警，写入数据库失败")
		} else {
			eventLog.Warn("文件告警")
		}
		eventLogfd.Close()

		// 发送邮箱告警
		if pkg.Cfg.AlertMode == ALERT_MODE_NONE {
			// logrus.Info("[告警] 邮件告警状态:关闭")
			return
		}
		logrus.Info("[告警] 正在推送邮件告警...")
		alertReceivers := strings.Split(tokenInfo.Alert_addr, ";")
		alertReceiverList := make([]string, 0, len(alertReceivers)) // 邮箱接收人列表

		// 去除每个接收者前后的空格，并验证邮箱格式
		for _, receiver := range alertReceivers {
			trimmedReceiver := strings.TrimSpace(receiver)
			if pkg.IsValidEmail(trimmedReceiver) {
				alertReceiverList = append(alertReceiverList, trimmedReceiver)
			} else {
				// logrus.Warnf("[Config] 无效的邮箱地址: %s", trimmedReceiver)
				continue
			}
		}

		switch pkg.Cfg.AlertMode {
		case ALERT_MODE_CLOUDMAIL:
			// send_mail(alertReceiver, msg, c.ClientIP(), c.GetHeader("User-Agent"), token) // 发送方式1：使用云邮件api发送警报邮件
			logrus.Warn("暂不支持云邮件告警模式，不发送邮件告警")

		case ALERT_MODE_STMPMAIL:
			res := pkg.SendTemplateMail( // 发送方式2：使用smtp发送邮件
				triggerInfo.Alert_msg,                     // 消息
				triggerInfo.Trigger_agent,                 // 用户agent
				triggerTime.Format("2006-01-02 15:04:05"), // 触发时间
				token,                  // token
				triggerInfo.Trigger_ip, // 触发ip
				alertReceiverList)      // 接收邮箱

			if res != nil {
				logrus.Error("[ERROR]邮件告警失败", res)
			} else {
				logrus.Info("[告警] 邮件告警推送发送成功")
			}

		default:
			logrus.Error("未知的邮件告警模式,不发送邮件告警")
		}
	}()

	// 返回页面
	c.HTML(http.StatusNotFound, "404.html", nil) // 返回404

}

func FingerprintHandle(c *gin.Context) {
	// 获取请求体原始数据
	var rawData map[string]interface{}
	if err := c.BindJSON(&rawData); err != nil {
		// 如果JSON解析失败，使用空map
		rawData = make(map[string]interface{})
	}

	// 安全地获取字段值，如果不存在则返回空字符串
	fingerprint := ""
	if fp, ok := rawData["fingerprint"]; ok {
		fingerprint = pkg.GetString(fp)
	}

	path := ""
	if p, ok := rawData["path"]; ok {
		path = pkg.GetString(p)
	}

	// 构建details，移除fingerprint和path字段
	details := make(map[string]interface{})
	for k, v := range rawData {
		if k != "fingerprint" && k != "path" {
			details[k] = v
		}
	}

	// JSON序列化details
	detailsJSON, err := json.Marshal(details)
	if err != nil {
		detailsJSON = []byte("{}") // 如果序列化失败，使用空对象
	}

	// 获取IP地址（如果获取不到则使用空字符串）
	ip := c.ClientIP()
	if ip == "" {
		ip = "unknown"
	}

	// 构建日志数据
	logData := pkg.FingerLogData{
		Time:        time.Now().Unix(),
		IP:          ip,
		Path:        path,
		Fingerprint: fingerprint,
		Details:     string(detailsJSON),
	}

	// 转换为JSON
	jsonData, err := json.Marshal(logData)
	if err != nil {
		logrus.Error("fingerprint 触发出错:日志转换失败")
		return
	}

	// 写入文件
	fingerprintLogPath := "log/fingerprint_log.json"
	f, err := os.OpenFile(fingerprintLogPath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		logrus.Error("fingerprint 触发出错:打开文件失败")
		return
	}
	defer f.Close()

	if _, err := f.WriteString(string(jsonData) + "\n"); err != nil {
		logrus.Error("fingerprint 触发出错:写入文件失败")
		return
	}

	c.HTML(http.StatusNotFound, "404.html", nil) // 返回404
}
