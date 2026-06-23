package handlers

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"server/internal/models"
	"server/internal/parasitic"
	"server/pkg"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/gorilla/websocket"
	"github.com/sirupsen/logrus"
	"gorm.io/gorm"
)

// 寄生蜜点全局状态
var (
	parasiticDetector    *parasitic.BotDetector
	parasiticSessionMgr  *parasitic.SessionManager
	parasiticProxyDetect *parasitic.ProxyDetector
	parasiticFingerMgr   *parasitic.FingerprintGroupManager
	parasiticMu          sync.Mutex
	parasiticInited      bool

	// WebSocket upgrader
	wsUpgrader = websocket.Upgrader{
		CheckOrigin: func(r *http.Request) bool {
			return true
		},
	}

	// 内存缓存
	logCache      []LogRecord
	logCacheMu    sync.RWMutex
	logCacheTimer *time.Timer
)

// LogRecord 统一日志记录
type LogRecord struct {
	Time              string   `json:"time"`
	RemoteIP          string   `json:"remote_ip"`
	IPs               []string `json:"ips"`
	ProxyDetectResult string   `json:"proxy_detect_result"`
	FingerprintData   string   `json:"fingerprint_data"`
	Fingerprint       string   `json:"fingerprint"`
	Target            string   `json:"target"`
	GroupID           int      `json:"group_id"`
	Score             int      `json:"score"`
	IsBot             bool     `json:"is_bot"`
	Reasons           []string `json:"reasons"`
	BotDetectMethod   string   `json:"bot_detect_method"`
}

// InitParasiticHandlers 初始化寄生蜜点处理器
func InitParasiticHandlers(db *gorm.DB) {
	parasiticMu.Lock()
	defer parasiticMu.Unlock()
	if parasiticInited {
		return
	}

	// 加载bots.json
	botsPath := filepath.Join(pkg.ProjectRootDir, "config", "bots.json")
	parasiticDetector = parasitic.NewBotDetector(botsPath)

	// 创建Session管理器
	parasiticSessionMgr = parasitic.NewSessionManager(db, pkg.Cfg.SessionTimeout)
	parasiticSessionMgr.StartMonitor()

	// 创建代理检测器
	parasiticProxyDetect = parasitic.NewProxyDetector()

	// 创建指纹分组管理器
	parasiticFingerMgr = parasitic.NewFingerprintGroupManager(db)

	// 启动日志缓存刷新
	go reloadLogCacheLoop(db)

	parasiticInited = true
	logrus.Info("[Parasitic] 寄生蜜点处理器初始化完成")
}

// reloadLogCacheLoop 定期刷新日志缓存
func reloadLogCacheLoop(db *gorm.DB) {
	ticker := time.NewTicker(10 * time.Second)
	defer ticker.Stop()

	// 立即刷新一次
	reloadLogCache(db)

	for range ticker.C {
		reloadLogCache(db)
	}
}

// reloadLogCache 从数据库加载日志到缓存
func reloadLogCache(db *gorm.DB) {
	var fingerprints []models.DeviceFingerprint
	if err := db.Order("id desc").Limit(1000).Find(&fingerprints).Error; err != nil {
		log.Printf("[Parasitic] 加载指纹缓存失败: %v", err)
		return
	}

	records := make([]LogRecord, 0, len(fingerprints))
	for _, fp := range fingerprints {
		// 解析WebRTC IPs
		var ips []string
		if fp.WebRTCIPs != "" {
			json.Unmarshal([]byte(fp.WebRTCIPs), &ips)
		}

		// 查询bot检测信息
		var botDet models.BotDetection
		botScore := 0
		isBot := false
		var reasons []string
		detectMethod := ""
		if fp.SessionToken != "" {
			result := db.Where("session_token = ?", fp.SessionToken).Order("id desc").Limit(1).Find(&botDet)
			if result.Error == nil && result.RowsAffected > 0 && botDet.ID > 0 {
				botScore = botDet.Score
				isBot = botDet.IsBot
				json.Unmarshal([]byte(botDet.Reasons), &reasons)
				detectMethod = botDet.DetectMethod
			} else if result.Error != nil {
				log.Printf("[Parasitic] query bot detection failed, session=%s err=%v", fp.SessionToken, result.Error)
			}
		}

		record := LogRecord{
			Time:              fp.Timestamp.Format(time.RFC3339),
			RemoteIP:          fp.RemoteIP,
			IPs:               ips,
			ProxyDetectResult: fp.ProxyDetectResult,
			FingerprintData:   fp.FingerprintData,
			Fingerprint:       fp.FingerprintID,
			Target:            fp.TargetURL,
			GroupID:           int(fp.GroupID),
			Score:             botScore,
			IsBot:             isBot,
			Reasons:           reasons,
			BotDetectMethod:   detectMethod,
		}
		records = append(records, record)
	}

	logCacheMu.Lock()
	logCache = records
	logCacheMu.Unlock()
}

// BotCheckHandler POST /bot-check
func BotCheckHandler(c *gin.Context) {
	enableCors(c)
	if c.Request.Method == http.MethodOptions {
		c.Status(http.StatusOK)
		return
	}

	var data parasitic.BotCheckRequest
	if err := c.ShouldBindJSON(&data); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid JSON: " + err.Error()})
		return
	}

	ip := c.ClientIP()
	if forwarded := c.GetHeader("X-Forwarded-For"); forwarded != "" {
		ip = strings.Split(forwarded, ",")[0]
	}

	// 获取或创建session
	session := &parasitic.SessionInfo{
		LastUpdate: time.Now(),
		UA:         data.UserAgent,
		IP:         ip,
	}

	// 构建鼠标轨迹带时间
	mouseTrackWithT := make([][]float64, 0, len(data.MouseTrack))
	if data.MouseMeta != nil && len(data.MouseMeta.Timestamps) > 0 {
		for i, point := range data.MouseTrack {
			if i < len(data.MouseMeta.Timestamps) && i < len(data.MouseMeta.Speeds) {
				mouseTrackWithT = append(mouseTrackWithT, []float64{
					point[0], point[1],
					data.MouseMeta.Timestamps[i],
					data.MouseMeta.Speeds[i],
				})
			} else if i < len(point) {
				mouseTrackWithT = append(mouseTrackWithT, []float64{
					point[0], point[1], 0, 0,
				})
			}
		}
	} else {
		for _, point := range data.MouseTrack {
			if len(point) >= 2 {
				mouseTrackWithT = append(mouseTrackWithT, []float64{point[0], point[1], 0, 0})
			}
		}
	}

	// 计算得分
	score, reasons := parasitic.CalcScorePublic(session, mouseTrackWithT, data.ClickIntervals, parasiticDetector)
	isBot := score >= parasitic.BotScoreThreshold

	// 保存到数据库
	if pkg.Db != nil {
		reasonsJSON, _ := json.Marshal(reasons)
		detection := models.BotDetection{
			SessionToken: data.SessionToken,
			IP:           ip,
			URL:          c.Request.URL.Path,
			UserAgent:    data.UserAgent,
			Score:        score,
			IsBot:        isBot,
			MousePoints:  len(data.MouseTrack),
			ClickCount:   len(data.ClickIntervals),
			Reasons:      string(reasonsJSON),
			DetectMethod: "advanced",
			Timestamp:    time.Now(),
		}
		if err := pkg.Db.Create(&detection).Error; err != nil {
			logrus.Errorf("[Parasitic] 保存Bot检测记录失败: %v", err)
		}
	}

	// 统一日志
	logUnified(ip, data.SessionToken, data.UserAgent, mouseTrackWithT, data.ClickIntervals, score, isBot, reasons)

	c.JSON(http.StatusOK, gin.H{
		"isBot":       isBot,
		"score":       score,
		"mousePoints": len(data.MouseTrack),
		"clickCount":  len(data.ClickIntervals),
	})
}

// FingerprintInfoHandler POST /info
func FingerprintInfoHandler(c *gin.Context) {
	enableCors(c)
	if c.Request.Method == http.MethodOptions {
		c.Status(http.StatusOK)
		return
	}

	ip := c.ClientIP()
	if forwarded := c.GetHeader("X-Forwarded-For"); forwarded != "" {
		ip = strings.Split(forwarded, ",")[0]
	}
	currentTime := time.Now()

	var fingerprintData map[string]interface{}
	if err := c.ShouldBindJSON(&fingerprintData); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Failed to decode JSON"})
		return
	}

	fingerprintID := fmt.Sprintf("%v", fingerprintData["fingerprint"])
	path := fmt.Sprintf("%v", fingerprintData["path"])
	sessionToken := ""
	if val, ok := fingerprintData["sessionToken"]; ok {
		sessionToken = fmt.Sprintf("%v", val)
	}
	delete(fingerprintData, "canvas")
	details, _ := json.Marshal(fingerprintData)

	// 写入本地日志
	logLine := fmt.Sprintf("Time: %s, RemoteIP: %s, Path: %v, Fingerprint: %v, Details: %v\n",
		currentTime.Format(time.RFC3339), ip, path, fingerprintID, string(details))
	appendToFile("log/fingerprint.log", logLine)

	logrus.Printf("[Fingerprint] RemoteIP: %s, Path: %v, Fingerprint: %v", ip, path, fingerprintID)

	// 存入SessionManager
	buf := parasiticSessionMgr.GetBuffer(ip)
	buf.SessionToken = sessionToken
	buf.FingerprintDetails = string(details)
	buf.Path = path
	buf.Fingerprint = fingerprintID
	buf.IsHTTPReady = true

	// 提取浏览器和OS信息
	if v, ok := fingerprintData["browser"]; ok {
		buf.Browser = fmt.Sprintf("%v", v)
	}
	if v, ok := fingerprintData["os"]; ok {
		buf.OS = fmt.Sprintf("%v", v)
	}
	if v, ok := fingerprintData["userAgent"]; ok {
		buf.UserAgent = fmt.Sprintf("%v", v)
	}

	parasiticSessionMgr.SignalReady(ip)
	c.Status(http.StatusOK)
}

// IPSHandler POST /ips
func IPSHandler(c *gin.Context) {
	enableCors(c)
	if c.Request.Method == http.MethodOptions {
		c.Status(http.StatusOK)
		return
	}

	var requestBody struct {
		IPs []string `json:"ips"`
	}
	if err := c.ShouldBindJSON(&requestBody); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Failed to parse JSON"})
		return
	}

	ip := c.ClientIP()
	if forwarded := c.GetHeader("X-Forwarded-For"); forwarded != "" {
		ip = strings.Split(forwarded, ",")[0]
	}

	// 写入本地日志
	logLine := fmt.Sprintf("Time: %v, RemoteIP: %s, IPs: %v\n", time.Now().Format(time.RFC3339), ip, requestBody.IPs)
	appendToFile("log/wrt_ips.log", logLine)
	logrus.Printf("[WebRTC] %v", logLine)

	// 存入SessionManager
	buf := parasiticSessionMgr.GetBuffer(ip)
	buf.Ips = requestBody.IPs
	buf.IsWebRTCReady = true

	parasiticSessionMgr.SignalReady(ip)
	c.Status(http.StatusOK)
}

// WSHandler GET /ws (WebSocket)
func WSHandler(c *gin.Context) {
	conn, err := wsUpgrader.Upgrade(c.Writer, c.Request, nil)
	if err != nil {
		logrus.Errorf("[Parasitic] WebSocket升级失败: %v", err)
		return
	}
	defer conn.Close()

	start := time.Now()
	if err := conn.WriteMessage(websocket.PingMessage, nil); err != nil {
		logrus.Errorf("[Parasitic] WebSocket ping发送失败: %v", err)
		return
	}
	_, _, err = conn.ReadMessage()
	if err != nil {
		logrus.Errorf("[Parasitic] WebSocket pong接收失败: %v", err)
		return
	}
	wsRTT := float64(time.Since(start).Milliseconds())

	clientIP := c.ClientIP()
	if forwarded := c.GetHeader("X-Forwarded-For"); forwarded != "" {
		clientIP = strings.Split(forwarded, ",")[0]
	}

	// 查询TCP RTT
	tcpRTT := 0.0
	if parasiticProxyDetect != nil {
		if rtt, err := parasiticProxyDetect.QueryTCPRTT(clientIP); err == nil {
			tcpRTT = rtt
		}
	}

	// 代理检测
	isProxy := false
	if parasiticProxyDetect != nil {
		isProxy = parasiticProxyDetect.DetectByRTT(wsRTT, tcpRTT)
	}

	// 存入SessionManager
	buf := parasiticSessionMgr.GetBuffer(clientIP)
	buf.WSRTT = wsRTT
	buf.TCPRTT = tcpRTT
	buf.IsWSReady = true

	// 写入延迟日志
	logLine := fmt.Sprintf("Time: %s, RemoteIP: %s, ProxyDetectResult: %v, details: %.2f,%.2f\n",
		time.Now().Format(time.RFC3339), clientIP, isProxy, tcpRTT, wsRTT)
	appendToFile("log/latency_log.log", logLine)

	parasiticSessionMgr.SignalReady(clientIP)

	// 返回RTT给客户端
	conn.WriteMessage(websocket.TextMessage, []byte(fmt.Sprintf("%.0f", wsRTT)))
}

// LogsHandler GET /api/logs
func LogsHandler(c *gin.Context) {
	page, _ := strconv.Atoi(c.DefaultQuery("page", "1"))
	size, _ := strconv.Atoi(c.DefaultQuery("size", "10"))
	if page < 1 {
		page = 1
	}
	if size < 1 || size > 100 {
		size = 10
	}

	filterTargets := parseCommaParam(c.Query("target"))
	filterBots := parseCommaParam(c.Query("is_bot"))
	filterProxies := parseCommaParam(c.Query("is_proxy"))
	filterOS := parseCommaParam(c.Query("os"))
	filterTZ := parseCommaParam(c.Query("timezone"))
	filterLangs := parseCommaParam(c.Query("language"))

	logCacheMu.RLock()
	defer logCacheMu.RUnlock()

	filteredLogs := make([]LogRecord, 0)
	optTargets := make(map[string]bool)
	optOS := make(map[string]bool)
	optTZ := make(map[string]bool)
	optLang := make(map[string]bool)

	for _, log := range logCache {
		// 解析FingerprintData获取筛选字段
		var fp fingerprintMeta
		if log.FingerprintData != "" {
			json.Unmarshal([]byte(log.FingerprintData), &fp)
		}

		currentTarget := log.Target
		if currentTarget == "" {
			currentTarget = fp.Path
		}
		if currentTarget == "" {
			currentTarget = fp.PathAlt
		}
		if currentTarget == "" {
			currentTarget = "Unknown"
		}

		// 收集选项
		if currentTarget != "Unknown" {
			optTargets[currentTarget] = true
		}
		if fp.OS != "" {
			optOS[fp.OS] = true
		}
		if fp.TimeZone != "" {
			optTZ[fp.TimeZone] = true
		}
		if fp.Language != "" {
			optLang[fp.Language] = true
		}

		// 应用筛选
		if !matchExact(filterTargets, currentTarget) {
			continue
		}
		if !matchExact(filterBots, strconv.FormatBool(log.IsBot)) {
			continue
		}
		if !matchExact(filterProxies, log.ProxyDetectResult) {
			continue
		}
		if !matchFilterContains(filterOS, fp.OS) {
			continue
		}
		if !matchExact(filterTZ, fp.TimeZone) {
			continue
		}
		if !matchExact(filterLangs, fp.Language) {
			continue
		}

		filteredLogs = append(filteredLogs, log)
	}

	// 排序（新到旧）
	sort.Slice(filteredLogs, func(i, j int) bool {
		return filteredLogs[i].Time > filteredLogs[j].Time
	})

	// 分页
	total := len(filteredLogs)
	start := (page - 1) * size
	if start > total {
		start = total
	}
	end := start + size
	if end > total {
		end = total
	}
	pageData := filteredLogs[start:end]

	c.JSON(http.StatusOK, gin.H{
		"code":  0,
		"total": total,
		"data":  pageData,
		"options": gin.H{
			"target":   mapKeys(optTargets),
			"os":       mapKeys(optOS),
			"timezone": mapKeys(optTZ),
			"language": mapKeys(optLang),
		},
	})
}

// TargetIPsHandler GET /internal/target-ips
func TargetIPsHandler(c *gin.Context) {
	targetParam := c.Query("target")
	if targetParam == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Target parameter is required"})
		return
	}

	logCacheMu.RLock()
	defer logCacheMu.RUnlock()

	uniqueIPs := make(map[string]bool)
	for _, log := range logCache {
		currentTarget := log.Target
		var fp fingerprintMeta
		if log.FingerprintData != "" {
			json.Unmarshal([]byte(log.FingerprintData), &fp)
		}
		if currentTarget == "" {
			currentTarget = fp.Path
		}
		if currentTarget == "" {
			currentTarget = fp.PathAlt
		}

		if currentTarget == targetParam && log.RemoteIP != "" {
			uniqueIPs[log.RemoteIP] = true
		}
	}

	resultIPs := make([]string, 0, len(uniqueIPs))
	for ip := range uniqueIPs {
		resultIPs = append(resultIPs, ip)
	}

	c.JSON(http.StatusOK, gin.H{
		"target": targetParam,
		"count":  len(resultIPs),
		"ips":    resultIPs,
	})
}

// PixelHandler GET /api/pixel
func PixelHandler(c *gin.Context) {
	ip := c.ClientIP()
	if forwarded := c.GetHeader("X-Forwarded-For"); forwarded != "" {
		ip = strings.Split(forwarded, ",")[0]
	}
	ua := c.Request.UserAgent()
	referer := c.GetHeader("Referer")
	if referer == "" {
		referer = "direct/unknown"
	}

	logLine := fmt.Sprintf("Time: %s | Type: CSS_TRACK | IP: %s | UA: %s | Ref: %s\n",
		time.Now().Format(time.RFC3339), ip, ua, referer)
	appendToFile("log/css_track.log", logLine)

	c.Header("Content-Type", "image/gif")
	c.Header("Cache-Control", "no-cache, no-store, must-revalidate")
	c.Header("Pragma", "no-cache")
	c.Header("Expires", "0")
	// 1x1透明GIF
	pixelData := []byte{0x47, 0x49, 0x46, 0x38, 0x39, 0x61, 0x01, 0x00, 0x01, 0x00, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0xff, 0xff, 0xff, 0x21, 0xf9, 0x04, 0x01, 0x00, 0x00, 0x00, 0x00, 0x2c, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x02, 0x01, 0x44, 0x00, 0x3b}
	c.Data(http.StatusOK, "image/gif", pixelData)
}

// 辅助类型
type fingerprintMeta struct {
	Path     string `json:"path"`
	PathAlt  string `json:"Path"`
	OS       string `json:"os"`
	TimeZone string `json:"timeZone"`
	Language string `json:"language"`
}

// 辅助函数
func enableCors(c *gin.Context) {
	origin := c.GetHeader("Origin")
	if origin == "" {
		origin = "*"
	}

	requestHeaders := c.GetHeader("Access-Control-Request-Headers")
	if requestHeaders == "" {
		requestHeaders = "Content-Type, Authorization, X-Client-Version"
	}

	c.Header("Access-Control-Allow-Origin", origin)
	c.Header("Vary", "Origin, Access-Control-Request-Method, Access-Control-Request-Headers, Access-Control-Request-Private-Network")
	c.Header("Access-Control-Allow-Methods", "POST, GET, OPTIONS")
	c.Header("Access-Control-Allow-Headers", requestHeaders)
	c.Header("Access-Control-Max-Age", "600")

	// Chrome 对访问本机/私网端口的跨域请求会增加 Private Network Access 预检。
	// 不回这个头时，浏览器会只发 OPTIONS，不再继续发正式的 POST /info /ips /bot-check。
	if strings.EqualFold(c.GetHeader("Access-Control-Request-Private-Network"), "true") {
		c.Header("Access-Control-Allow-Private-Network", "true")
	}
}

func appendToFile(filePath string, content string) {
	dir := filepath.Dir(filePath)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return
	}
	f, err := os.OpenFile(filePath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		return
	}
	defer f.Close()
	f.WriteString(content)
}

func parseCommaParam(val string) []string {
	if val == "" {
		return nil
	}
	parts := strings.Split(val, ",")
	result := make([]string, 0, len(parts))
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p != "" {
			result = append(result, p)
		}
	}
	return result
}

func matchExact(filters []string, val string) bool {
	if len(filters) == 0 {
		return true
	}
	for _, f := range filters {
		if strings.EqualFold(strings.TrimSpace(f), strings.TrimSpace(val)) {
			return true
		}
	}
	return false
}

func matchFilterContains(filters []string, val string) bool {
	if len(filters) == 0 {
		return true
	}
	for _, f := range filters {
		if strings.Contains(strings.ToLower(val), strings.ToLower(f)) {
			return true
		}
	}
	return false
}

func mapKeys(m map[string]bool) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		if k != "" {
			keys = append(keys, k)
		}
	}
	sort.Strings(keys)
	return keys
}

// logUnified 写入统一日志
func logUnified(ip, sessionToken, ua string, mouseTrack [][]float64, clickIntervals []float64, score int, isBot bool, reasons []string) {
	reasonsJSON, _ := json.Marshal(reasons)
	logLine := fmt.Sprintf(`{"time":"%s","ip":"%s","session":"%s","ua":"%s","score":%d,"is_bot":%v,"reasons":%s,"mouse_points":%d,"click_count":%d}`+"\n",
		time.Now().Format(time.RFC3339Nano),
		ip, sessionToken, escapeJSON(ua),
		score, isBot, string(reasonsJSON),
		len(mouseTrack), len(clickIntervals))
	appendToFile("log/unified.log", logLine)
}

func escapeJSON(s string) string {
	b, _ := json.Marshal(s)
	return string(b)
}

// RequestTypeMiddleware 请求类型中间件
func RequestTypeMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		requestType := c.GetHeader("X-Request-Type")
		if requestType == "" {
			if strings.Contains(c.Request.URL.Path, "bot-check") {
				requestType = "api"
			} else {
				requestType = "original"
			}
		}
		c.Set("request_type", requestType)
		c.Next()
	}
}
