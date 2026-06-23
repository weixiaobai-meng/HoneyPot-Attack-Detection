package handlers

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/url"
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
	ALERT_MODE_NONE      = 0
	ALERT_MODE_STMPMAIL  = 1
	ALERT_MODE_CLOUDMAIL = 2
)

var eventLogger = logrus.New()

// TriggerHandler handles file honeypot callback requests.
func TriggerHandler(c *gin.Context) {
	eventLogfd, err := os.OpenFile("log/event.log", os.O_RDWR|os.O_CREATE|os.O_APPEND, 0666)
	if err != nil {
		logrus.Fatal("open file error")
	}

	eventLogger.SetOutput(eventLogfd)

	var token string
	if t, exist := c.Get("token"); exist {
		token = normalizeTriggerToken(t.(string))
	} else {
		token = normalizeTriggerToken(c.Param("token"))
	}

	go func() {
		defer eventLogfd.Close()

		var srcIP string
		if ip, exists := c.Get("clientIp"); exists {
			srcIP = ip.(string)
		} else {
			srcIP = c.GetHeader("X-Forwarded-For")
			if srcIP == "" {
				srcIP = c.ClientIP()
			}
		}

		requestURL := c.Request.URL.String()
		if strings.Contains(token, "'") {
			logrus.Warn("[Warning] suspicious SQL injection, ip:", srcIP)
			secLog := models.SecurityLog{
				Trigger_time: time.Now(),
				Src_ip:       srcIP,
				Event:        "sql injection",
				Url:          requestURL,
			}
			models.Insert_securityLog(pkg.Db, &secLog)
			return
		}

		tokenInfo, err := models.FindAlertMsg(pkg.Db, token)
		if errors.Is(err, gorm.ErrRecordNotFound) {
			logrus.Warn("[Warning] suspicious path probing,", srcIP, ",", requestURL)
			secLog := models.SecurityLog{
				Trigger_time: time.Now(),
				Src_ip:       srcIP,
				Event:        "url probe",
				Url:          requestURL,
			}
			models.Insert_securityLog(pkg.Db, &secLog)
			return
		}
		if err != nil {
			logrus.Error("[Error] find token info failed:", err)
			return
		}

		eventLogger.SetFormatter(&logrus.JSONFormatter{
			TimestampFormat: "2006-01-02 15:04:05",
		})
		eventLog := eventLogger.WithFields(logrus.Fields{
			"message":    tokenInfo.Alert_msg,
			"token":      token,
			"trigger_ip": srcIP,
			"ip":         srcIP,
			"User-Agent": c.GetHeader("User-Agent"),
		})

		logrus.Info("[Alert] file honeypot triggered, ip:", srcIP, " message:", tokenInfo.Alert_msg)

		tokenURL := buildPublicTokenURL(token)
		loc, err := time.LoadLocation("Asia/Shanghai")
		if err != nil {
			logrus.Error("load time location failed", err)
			return
		}
		triggerTime := time.Now().UTC().In(loc)

		triggerInfo := models.TriggerInfo{
			Token:         token,
			Token_url:     tokenURL,
			Trigger_time:  triggerTime,
			Trigger_ip:    c.ClientIP(),
			Alert_addr:    tokenInfo.Alert_addr,
			Alert_msg:     tokenInfo.Alert_msg,
			Trigger_agent: c.GetHeader("User-Agent"),
		}
		ret := models.Insert_trigger(pkg.Db, &triggerInfo)
		if ret != 0 {
			eventLog.Warn("file alert database insert failed")
		} else {
			eventLog.Warn("file alert")
		}

		if pkg.Cfg.AlertMode == ALERT_MODE_NONE {
			return
		}

		alertReceivers := strings.Split(tokenInfo.Alert_addr, ";")
		alertReceiverList := make([]string, 0, len(alertReceivers))
		for _, receiver := range alertReceivers {
			trimmed := strings.TrimSpace(receiver)
			if pkg.IsValidEmail(trimmed) {
				alertReceiverList = append(alertReceiverList, trimmed)
			}
		}

		switch pkg.Cfg.AlertMode {
		case ALERT_MODE_CLOUDMAIL:
			logrus.Warn("cloud mail alert mode is not supported yet")
		case ALERT_MODE_STMPMAIL:
			res := pkg.SendTemplateMail(
				triggerInfo.Alert_msg,
				triggerInfo.Trigger_agent,
				triggerTime.Format("2006-01-02 15:04:05"),
				token,
				triggerInfo.Trigger_ip,
				alertReceiverList,
			)
			if res != nil {
				logrus.Error("[Error] mail alert failed", res)
			} else {
				logrus.Info("[Alert] mail alert sent successfully")
			}
		default:
			logrus.Error("unknown mail alert mode")
		}
	}()

	c.HTML(http.StatusNotFound, "404.html", nil)
}

// FingerprintHandle stores the legacy fingerprint POST used by file detections.
func FingerprintHandle(c *gin.Context) {
	var rawData map[string]interface{}
	if err := c.BindJSON(&rawData); err != nil {
		rawData = make(map[string]interface{})
	}

	fingerprint := ""
	if fp, ok := rawData["fingerprint"]; ok {
		fingerprint = pkg.GetString(fp)
	}

	path := ""
	if p, ok := rawData["path"]; ok {
		path = pkg.GetString(p)
	}

	details := make(map[string]interface{})
	for k, v := range rawData {
		if k != "fingerprint" && k != "path" {
			details[k] = v
		}
	}

	detailsJSON, err := json.Marshal(details)
	if err != nil {
		detailsJSON = []byte("{}")
	}

	ip := c.ClientIP()
	if ip == "" {
		ip = "unknown"
	}

	logData := pkg.FingerLogData{
		Time:        time.Now().Unix(),
		IP:          ip,
		Path:        path,
		Fingerprint: fingerprint,
		Details:     string(detailsJSON),
	}

	jsonData, err := json.Marshal(logData)
	if err != nil {
		logrus.Error("fingerprint trigger error: marshal failed")
		return
	}

	fingerprintLogPath := "log/fingerprint_log.json"
	f, err := os.OpenFile(fingerprintLogPath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		logrus.Error("fingerprint trigger error: open file failed")
		return
	}
	defer f.Close()

	if _, err := f.WriteString(string(jsonData) + "\n"); err != nil {
		logrus.Error("fingerprint trigger error: write file failed")
		return
	}

	c.HTML(http.StatusNotFound, "404.html", nil)
}

func normalizeTriggerToken(tokenPath string) string {
	tokenPath = strings.Trim(strings.TrimSpace(tokenPath), "/")
	if tokenPath == "" {
		return ""
	}

	if strings.HasPrefix(tokenPath, "http://") || strings.HasPrefix(tokenPath, "https://") {
		if parsed, err := url.Parse(tokenPath); err == nil {
			tokenPath = strings.Trim(parsed.Path, "/")
		}
	}

	switch {
	case strings.HasPrefix(tokenPath, "static/img/logo-"):
		tokenPath = strings.TrimPrefix(tokenPath, "static/img/logo-")
	case strings.HasPrefix(tokenPath, "contact/"):
		tokenPath = strings.TrimPrefix(tokenPath, "contact/")
	case strings.HasPrefix(tokenPath, "logo-"):
		tokenPath = strings.TrimPrefix(tokenPath, "logo-")
	}

	tokenPath = strings.TrimSuffix(tokenPath, ".png")
	tokenPath, _ = url.PathUnescape(tokenPath)
	return strings.Trim(strings.TrimSpace(tokenPath), "/")
}
