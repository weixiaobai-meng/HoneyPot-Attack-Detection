package handlers

import (
	"encoding/json"
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

// AccountAlertHandler POST /account/alert
// 接收 ssh-vpn 发送的账户蜜点告警（格式与 systemwire2 原有端点兼容）
func AccountAlertHandler(c *gin.Context) {
	var rawData map[string]interface{}
	if err := c.ShouldBindJSON(&rawData); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"code": 1, "message": "Invalid JSON: " + err.Error(), "data": struct{}{}})
		return
	}

	// 字段提取（兼容 ssh-vpn JSON 字段名）
	srcIP := firstNonEmpty(rawData, "src", "src_ip")
	srcPort := firstNonEmpty(rawData, "spt", "src_port")
	dstIP := firstNonEmpty(rawData, "dst", "dst_ip")
	dstPort := firstNonEmpty(rawData, "dpt", "dst_port")
	username := firstNonEmpty(rawData, "duser", "username")
	password := firstNonEmpty(rawData, "password")
	clientVersion := firstNonEmpty(rawData, "client_version")
	msg := firstNonEmpty(rawData, "msg")       // Connection / Request with password
	protocol := strings.ToLower(firstNonEmpty(rawData, "protocol", "ssh"))

	// 兼容 src 为 ip:port 格式
	host, port, err := netSplitHostPort(srcIP)
	if err == nil && port != "" {
		srcIP, srcPort = host, port
	}

	// 参数校验
	if protocol == "" {
		protocol = "ssh"
	}

	rawEventBytes, _ := json.Marshal(rawData)

	triggerTime := time.Now()
	if tv, ok := rawData["time"]; ok {
		switch v := tv.(type) {
		case float64:
			triggerTime = time.Unix(int64(v), 0)
		case int64:
			triggerTime = time.Unix(v, 0)
		case string:
			if t, err := time.Parse(time.RFC3339, v); err == nil {
				triggerTime = t
			}
		}
	}

	record := models.AccountAlert{
		TriggerTime:   triggerTime,
		ReportTime:    time.Now(),
		SrcIP:         srcIP,
		SrcPort:       srcPort,
		DstIP:         dstIP,
		DstPort:       dstPort,
		Username:      username,
		Password:      password,
		ClientVersion: clientVersion,
		Protocol:      protocol,
		Message:       msg,
		RawEvent:      string(rawEventBytes),
	}

	if pkg.Db == nil {
		c.JSON(http.StatusInternalServerError, gin.H{"code": 1, "message": "database not initialized", "data": struct{}{}})
		return
	}

	if err := pkg.Db.Create(&record).Error; err != nil {
		logrus.Errorf("[AccountAlert] 入库失败: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"code": 1, "message": "insert failed", "data": struct{}{}})
		return
	}

	logrus.Infof("[AccountAlert] 账户告警已记录: src=%s, user=%s, proto=%s, msg=%s", srcIP, username, protocol, msg)
	c.JSON(http.StatusOK, gin.H{"code": 0, "message": "Success", "data": gin.H{"id": record.ID}})
}

// AccountAlertsHandler GET /api/account-alerts
// 供 systemwire2 定时拉取（分页、按时间筛选）
func AccountAlertsHandler(c *gin.Context) {
	page, _ := strconv.Atoi(c.DefaultQuery("page", "1"))
	size, _ := strconv.Atoi(c.DefaultQuery("size", "100"))
	if page < 1 {
		page = 1
	}
	if size < 1 || size > 500 {
		size = 100
	}

	since := c.Query("since") // ISO时间，用于增量拉取

	if pkg.Db == nil {
		c.JSON(http.StatusOK, gin.H{"code": 0, "total": 0, "data": []struct{}{}})
		return
	}

	query := pkg.Db.Model(&models.AccountAlert{}).Order("id desc")

	if since != "" {
		if t, err := time.Parse(time.RFC3339, since); err == nil {
			query = query.Where("trigger_time > ?", t)
		} else if t, err := time.Parse("2006-01-02 15:04:05", since); err == nil {
			query = query.Where("trigger_time > ?", t)
		} else if t, err := time.Parse("2006-01-02T15:04:05", since); err == nil {
			query = query.Where("trigger_time > ?", t)
		}
	}

	var total int64
	query.Count(&total)

	var records []models.AccountAlert
	if err := query.Offset((page - 1) * size).Limit(size).Find(&records).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"code": 1, "message": "query failed", "data": struct{}{}})
		return
	}

	data := make([]gin.H, 0, len(records))
	for _, r := range records {
		data = append(data, gin.H{
			"id":             r.ID,
			"trigger_time":   r.TriggerTime.Format(time.RFC3339),
			"report_time":    r.ReportTime.Format(time.RFC3339),
			"src_ip":         r.SrcIP,
			"src_port":       r.SrcPort,
			"dst_ip":         r.DstIP,
			"dst_port":       r.DstPort,
			"username":       r.Username,
			"password":       r.Password,
			"client_version": r.ClientVersion,
			"protocol":       r.Protocol,
			"message":        r.Message,
			"raw_event":      r.RawEvent,
		})
	}

	c.JSON(http.StatusOK, gin.H{
		"code":  0,
		"total": total,
		"data":  data,
	})
}

// 辅助：从 map 中取第一个非空值
func firstNonEmpty(m map[string]interface{}, keys ...string) string {
	for _, key := range keys {
		if v, ok := m[key]; ok && v != nil {
			s := fmt.Sprintf("%v", v)
			if strings.TrimSpace(s) != "" {
				return strings.TrimSpace(s)
			}
		}
	}
	return ""
}

// 辅助：分割 host:port
func netSplitHostPort(addr string) (string, string, error) {
	if !strings.Contains(addr, ":") {
		return addr, "", nil
	}
	parts := strings.Split(addr, ":")
	if len(parts) == 2 {
		return parts[0], parts[1], nil
	}
	// IPv6 不处理
	return addr, "", fmt.Errorf("invalid addr: %s", addr)
}

