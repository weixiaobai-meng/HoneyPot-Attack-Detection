package main

import (
	"encoding/json"
	"net/http"
	"os"
	"strings"
	"time"
	"fmt"
	"log"
	"net"

	"strconv"

	"github.com/gorilla/websocket"
	

)

// func mainHandler(w http.ResponseWriter, r *http.Request) {
// 	// 返回前端HTML
// 	htmlBytes, err := os.ReadFile("/var/www/front/index.html")
// 	if err != nil {
// 		return
// 	}

// 	w.Header().Set("Content-Type", "text/html; charset=utf-8")
// 	w.Write(htmlBytes)
// }
func mainHandler(w http.ResponseWriter, r *http.Request) {
    // === 1. 定义陷阱列表 (Map结构) ===
    // Key(左边) = 陷阱路径
    // Value(右边) = 对应的伪造返回内容
    traps := map[string]string{
        "/config.json": `{"db_host": "10.0.0.5", "secret": "sk-fake-token"}`,
        "/.env":        `DB_PASSWORD=root_pass_123\nAWS_KEY=AKIAIOSFODNN7EXAMPLE`,
        "/backup.sql":  `-- MySQL dump 10.13\n-- Host: localhost\nINSERT INTO users VALUES (1, 'admin', 'md5_hash');`,
        "/web.rar":     "Error: File is corrupted", // 假装文件损坏，骗他下载
        "/admin/":      "<h1>403 Forbidden</h1>",   // 假装有后台但没权限
    }

    // === 2. 检查当前请求是否踩中陷阱 ===
    // traps[r.URL.Path] 会尝试在 map 里找当前路径
    // 如果找到了，ok 为 true，fakeContent 就是上面的伪造内容
    if fakeContent, ok := traps[r.URL.Path]; ok {
        ip := getClientIP(r)

        // 🚨 记录攻击 (调用独立的记录函数)
        go RecordHoneypotHit(ip, r.URL.Path, r.UserAgent())

        // 根据文件类型设置一下 Header，演得像一点
        if strings.HasSuffix(r.URL.Path, ".json") {
            w.Header().Set("Content-Type", "application/json")
        } else {
            w.Header().Set("Content-Type", "text/plain")
        }

        // 返回伪造数据
        w.WriteHeader(http.StatusOK)
        w.Write([]byte(fakeContent))
        return // 结束战斗，不要返回真的网页
    }

    // === 3. 正常用户的逻辑 (只有没踩中陷阱才会走到这里) ===
    // 你的网页入口通常是 "/" 或者 "/index.html"
    if r.URL.Path == "/" || r.URL.Path == "/index.html" {
        htmlBytes, err := os.ReadFile("/var/www/front/index.html")
        if err != nil {
            http.NotFound(w, r)
            return
        }
        w.Header().Set("Content-Type", "text/html; charset=utf-8")
        w.Write(htmlBytes)
        return
    }

    // === 4. 处理静态资源或其他不存在的路径 ===
    // 如果既不是陷阱，也不是首页，可能是 css/js 或者真的不存在
    // 这里简单处理为 404，或者你可以交给 http.FileServer 处理静态文件
    http.NotFound(w, r)
}

func botCheckHandler(w http.ResponseWriter, r *http.Request) {
	//startTime := time.Now()

	var data BotCheckRequest
	if err := json.NewDecoder(r.Body).Decode(&data); err != nil {
		log.Printf("[错误] 无效的JSON请求: %v", err)
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]string{
			"error": "Invalid JSON: " + err.Error(),
		})
		return
	}

	ip := getClientIP(r)

	// 建立 IP ↔ Session 关系
	recentIPs.RLock()
	_, seen := recentIPs.data[ip]
	recentIPs.RUnlock()

	if seen {
		ipToSession.Lock()
		ipToSession.data[ip] = data.SessionToken
		ipToSession.Unlock()
	}

	// 获取基础日志
	var baseLog *BaseLog
    pendingLogs.Lock()
	// log.Printf("[调试] === 开始查找基础日志 ===")
	// log.Printf("[调试] 查找IP: %s", ip)
	// log.Printf("[调试] pendingLogs映射大小: %d", len(pendingLogs.data))
    
	if log, exists := pendingLogs.data[ip]; exists {
        baseLog = log
        delete(pendingLogs.data, ip) // 移出队列
    }
    pendingLogs.Unlock()
	// log.Printf("[调试] 找到基础日志: %+v", baseLog)

	// 获取或创建 session
	sessions.Lock()
	s, ok := sessions.data[data.SessionToken]
	if !ok {
		s = &SessionInfo{
			LastUpdate: time.Now(),
			Requests:   []time.Time{},
			UA:         data.UserAgent,
			IP:         ip,
		}
		sessions.data[data.SessionToken] = s
	}
	sessions.Unlock()

	mouseTrackWithT := combineMouseTrackWithT(data)
	score := calcScore(s, mouseTrackWithT, data.ClickIntervals)
	isBot := score >= BotScoreThreshold

	// 收集判断依据
	var reasons []string
	if detector.IsBot(data.UserAgent) {
		reasons = append(reasons, "UA匹配Bot规则")
	}
	if len(mouseTrackWithT) < 5 {
		reasons = append(reasons, "鼠标轨迹点过少")
	} else if isRegularMouseTrack(mouseTrackWithT) {
		reasons = append(reasons, "鼠标轨迹过于规律")
	}
	if len(data.ClickIntervals) > 1 {
		if variance := calculateClickVariance(data.ClickIntervals); variance < 1000 {
			reasons = append(reasons, fmt.Sprintf("点击间隔过于规律(方差=%.2f)", variance))
		}
	} else if len(data.ClickIntervals) == 0 {
		reasons = append(reasons, "无点击事件记录")
	}
	if len(s.Requests) > 2 {
		if freqScore := analyzeRequestFrequency(s.Requests); freqScore > 0 {
			reasons = append(reasons, fmt.Sprintf("请求频率异常(得分+%d)", freqScore))
		}
	}
	if strings.Contains(strings.ToLower(data.UserAgent), "headlesschrome") {
		reasons = append(reasons, "HeadlessChrome UA")
	}

	// 构建检测日志
	detectionLog := &DetectionLog{
		Timestamp:   time.Now().Format(time.RFC3339Nano),
		SessionID:   data.SessionToken,
		IP:			 ip,
		Score:       score,
		MousePoints: len(mouseTrackWithT),
		ClickCount:  len(data.ClickIntervals),
		Reasons:     reasons,
		IsBot:       score >= BotScoreThreshold,
		RequestURL:  r.URL.Path,
		Method:      r.Method,
		DetectMethod: "advanced", // 使用正确的字段名
	}

    // 输出合并日志
    logUnified(UnifiedLog{
        Base:       baseLog,
        Detection:  detectionLog,
        Abnormal:   baseLog == nil, // 标记是否缺少基础日志
    })

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"isBot":       isBot,
		"score":       score,
		"mousePoints": len(mouseTrackWithT),
		"clickCount":  len(data.ClickIntervals),
	})
}


// 新增的WebSocket处理器
func handleWebSocket(w http.ResponseWriter, r *http.Request) {
	conn, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		log.Println("WebSocket upgrade failed:", err)
		return
	}
	defer conn.Close()

	start := time.Now()
	if err := conn.WriteMessage(websocket.PingMessage, nil); err != nil {
		log.Println("WebSocket ping failed:", err)
		return
	}
	_, _, err = conn.ReadMessage()
	if err != nil {
		log.Println("WebSocket response failed:", err)
		return
	}
	wsRTT := float64(time.Since(start).Milliseconds())

	remoteAddr := getClientIP(r)

	connLatencyMutex.Lock()
	if _, ok := connLatencyMap[remoteAddr]; !ok {
		connLatencyMap[remoteAddr] = &latency{}
	}
	connLatencyMap[remoteAddr].WSRTT = wsRTT
	connLatencyMap[remoteAddr].ICMPRTT = 0
	connLatencyMutex.Unlock()

	tcpRTT := waitForTCPRTT(remoteAddr, 5000*time.Millisecond)

	connLatencyMutex.Lock()
	connLatencyMap[remoteAddr].TCPRTT = tcpRTT
	connLatencyMutex.Unlock()

	logLatency(remoteAddr)
}

// 新增的IPS处理器
// func handleIPS(w http.ResponseWriter, r *http.Request) {
// 	enableCors(&w, r)

// 	if r.Method == http.MethodOptions {
// 		w.WriteHeader(http.StatusOK)
// 		return
// 	}

// 	if r.Method != http.MethodPost {
// 		http.Error(w, "Invalid request method", http.StatusMethodNotAllowed)
// 		return
// 	}

// 	var requestBody struct {
// 		IPs []string `json:"ips"`
// 	}
// 	err := json.NewDecoder(r.Body).Decode(&requestBody)
// 	if err != nil {
// 		http.Error(w, "Failed to parse JSON body", http.StatusBadRequest)
// 		log.Println(err)
// 		return
// 	}

// 	remoteAddr := getClientIP(r)
// 	logLine := fmt.Sprintf("Time: %v, RemoteIP: %s, IPs: %v\n", time.Now().Format(time.RFC3339), remoteAddr, requestBody.IPs)

// 	if _, ok := dataMap[remoteAddr]; !ok {
// 		dataMap[remoteAddr] = &parasitism{}
// 	}

// 	dataMap[remoteAddr].Time = time.Now().Format(time.RFC3339)
// 	dataMap[remoteAddr].RemoteIP = remoteAddr
// 	dataMap[remoteAddr].Ips = requestBody.IPs

// 	err = appendToFile("log/wrt_ips.log", logLine)
// 	if err != nil {
// 		http.Error(w, fmt.Sprintf("Failed to write to log file: %v", err), http.StatusInternalServerError)
// 		return
// 	}

// 	log.Printf("[webRTC] %v", logLine)
// 	w.WriteHeader(http.StatusOK)
// 	w.Write([]byte("IP addresses logged successfully"))
// }
func handleIPS(w http.ResponseWriter, r *http.Request) {
	enableCors(&w, r)
	if r.Method == http.MethodOptions {
		w.WriteHeader(http.StatusOK)
		return
	}
	if r.Method != http.MethodPost {
		http.Error(w, "Invalid request method", http.StatusMethodNotAllowed)
		return
	}

	var requestBody struct {
		IPs []string `json:"ips"`
	}
	err := json.NewDecoder(r.Body).Decode(&requestBody)
	if err != nil {
		http.Error(w, "Failed to parse JSON body", http.StatusBadRequest)
		log.Println(err)
		return
	}

	ipAddress := getClientIP(r)

	// 本地文件日志 (保留你原来的逻辑)
	logLine := fmt.Sprintf("Time: %v, RemoteIP: %s, IPs: %v\n", time.Now().Format(time.RFC3339), ipAddress, requestBody.IPs)
	appendToFile("log/wrt_ips.log", logLine)
	log.Printf("[WebRTC] %v", logLine)

	// ==========================================
	// 🛠️ 修改部分：使用 SessionManager
	// ==========================================

	// 1. 获取 Buffer
	buf := sm.GetBuffer(ipAddress)

	// 2. 更新 WebRTC 数据 (加锁)
	sm.mu.Lock()
	buf.Data.Ips = requestBody.IPs // 存入 IP 数组
	buf.IsWebRTCReady = true       // 🚩 标记 WebRTC 就绪
	sm.mu.Unlock()

	// 3. 发送信号
	select {
	case sm.checkCh <- ipAddress:
	default:
	}

	w.WriteHeader(http.StatusOK)
	w.Write([]byte("IP addresses logged successfully"))
}

// 新增的POST处理器
// func handlePost(w http.ResponseWriter, r *http.Request) {
// 	enableCors(&w, r)
// 	if r.Method == http.MethodOptions {
// 		w.WriteHeader(http.StatusOK)
// 		return
// 	}

// 	if r.Method != http.MethodPost {
// 		http.Error(w, "Invalid request method", http.StatusMethodNotAllowed)
// 		log.Println("[INFO] Invalid request method")
// 		return
// 	}

// 	loc, _ := time.LoadLocation("Asia/Shanghai")
// 	time.Local = loc

// 	ipAddress := getClientIP(r)
// 	currentTime := time.Now().Format(time.RFC3339)

// 	var fingerprintData map[string]interface{}
// 	err := json.NewDecoder(r.Body).Decode(&fingerprintData)
// 	if err != nil {
// 		http.Error(w, "Failed to decode JSON data", http.StatusBadRequest)
// 		log.Println("[INFO] Failed to decode JSON data")
// 		return
// 	}

// 	fingerprintID := fmt.Sprintf("%v", fingerprintData["fingerprint"])
// 	path := fmt.Sprintf("%v", fingerprintData["path"])
// 	realPath := path
// 	delete(fingerprintData, "path")
// 	delete(fingerprintData, "canvas")
	

// 	sessionToken := ""
// 	if val, ok := fingerprintData["sessionToken"]; ok {
// 		sessionToken = fmt.Sprintf("%v", val)
// 	}

// 	details, err := json.Marshal(fingerprintData)
// 	if err != nil {
// 		http.Error(w, "Failed to encode details to JSON", http.StatusInternalServerError)
// 		log.Println("[INFO] Failed to encode details to JSON")
// 		return
// 	}

// 	logLine := fmt.Sprintf(
// 		"Time: %s, RemoteIP: %s, Path: %v, Fingerprint: %v, Details: %v\n",
// 		currentTime,
// 		ipAddress,
// 		realPath,
// 		fingerprintID,
// 		string(details),
// 	)
	// log.Printf("[Fingerprint] RemoteIP: %s, Path: %v, Fingerprint: %v",
	// 	ipAddress,
	// 	realPath,
	// 	fingerprintID,
	// )
// 	if _, ok := dataMap[ipAddress]; !ok {
// 		dataMap[ipAddress] = &parasitism{}
// 	}

// 	dataMap[ipAddress].Path = realPath
// 	dataMap[ipAddress].Fingerprint = fingerprintID
// 	dataMap[ipAddress].SessionToken = sessionToken
// 	log.Printf(dataMap[ipAddress].SessionToken)
// 	dataMap[ipAddress].FingerprintDetails = string(details)

// 	err = appendToFile("log/fingerprint.log", logLine)
// 	if err != nil {
// 		http.Error(w, "Failed to write to file", http.StatusInternalServerError)
// 		return
// 	}

// 	w.WriteHeader(http.StatusOK)
// }

func handlePost(w http.ResponseWriter, r *http.Request) {
	enableCors(&w, r)
	if r.Method == http.MethodOptions {
		w.WriteHeader(http.StatusOK)
		return
	}
	if r.Method != http.MethodPost {
		http.Error(w, "Invalid request method", http.StatusMethodNotAllowed)
		return
	}

	loc, _ := time.LoadLocation("Asia/Shanghai")
	time.Local = loc

	ipAddress := getClientIP(r)
	currentTime := time.Now().Format(time.RFC3339)

	var fingerprintData map[string]interface{}
	err := json.NewDecoder(r.Body).Decode(&fingerprintData)
	if err != nil {
		http.Error(w, "Failed to decode JSON data", http.StatusBadRequest)
		return
	}

	fingerprintID := fmt.Sprintf("%v", fingerprintData["fingerprint"])
	path := fmt.Sprintf("%v", fingerprintData["path"])
	realPath := path
	delete(fingerprintData, "canvas")

	sessionToken := ""
	if val, ok := fingerprintData["sessionToken"]; ok {
		sessionToken = fmt.Sprintf("%v", val)
	}

	details, err := json.Marshal(fingerprintData)
	if err != nil {
		http.Error(w, "Failed to encode details", http.StatusInternalServerError)
		return
	}

	// 本地文件日志 (保留)
	logLine := fmt.Sprintf(
		"Time: %s, RemoteIP: %s, Path: %v, Fingerprint: %v, Details: %v\n",
		currentTime, ipAddress, realPath, fingerprintID, string(details),
	)
	appendToFile("log/fingerprint.log", logLine)


	log.Printf("[Fingerprint] RemoteIP: %s, Path: %v, Fingerprint: %v", ipAddress, realPath, fingerprintID)

	// ==========================================
	// 🛠️ 修改部分：使用 SessionManager
	// ==========================================

	// 1. 获取 Buffer
	buf := sm.GetBuffer(ipAddress)

	// 2. 更新 HTTP 数据 (加锁)
	sm.mu.Lock()
	buf.Data.SessionToken = sessionToken
	buf.Data.FingerprintDetails = string(details)
	buf.Data.Path = realPath
	buf.Data.Fingerprint = fingerprintID

	buf.IsHTTPReady = true // 🚩 标记 HTTP 就绪
	sm.mu.Unlock()

	// 3. 发送信号
	select {
	case sm.checkCh <- ipAddress:
	default:
	}

	w.WriteHeader(http.StatusOK)
}


// 辅助结构体：仅用于解析 FingerprintData 中的关键字段
type FingerprintMeta struct {
	Path     string `json:"path"`
	PathAlt  string `json:"Path"` // 兼容大小写
	OS       string `json:"os"`
	TimeZone string `json:"timeZone"`
	Language string `json:"language"`
}

// 核心日志查询接口 (支持筛选 + 综合代理判定逻辑)
func logHandler(w http.ResponseWriter, r *http.Request) {
	enableCors(&w, r)
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// === 1. 解析参数 ===
	q := r.URL.Query()
	
	page, _ := strconv.Atoi(q.Get("page"))
	size, _ := strconv.Atoi(q.Get("size"))
	if page < 1 { page = 1 }
	if size < 1 || size > 100 { size = 10 }

	// 筛选参数提取器
	parseParam := func(key string) []string {
		val := q.Get(key)
		if val == "" { return nil }
		return strings.Split(val, ",")
	}

	filterTargets := parseParam("target")
	filterBots    := parseParam("is_bot")
	filterProxies := parseParam("is_proxy") // 前端传 "true" 或 "false"
	filterOS      := parseParam("os")
	filterTZ      := parseParam("timezone")
	filterLangs   := parseParam("language")

	cacheMutex.RLock()
	defer cacheMutex.RUnlock()

	filteredLogs := make([]LogRecord, 0)

	// Options Sets
	optTargets := make(map[string]bool)
	optOS      := make(map[string]bool)
	optTZ      := make(map[string]bool)
	optLang    := make(map[string]bool)

	// 通用匹配函数
	matchExact := func(filters []string, val string) bool {
		if len(filters) == 0 { return true }
		for _, f := range filters {
			if strings.EqualFold(strings.TrimSpace(f), strings.TrimSpace(val)) {
				return true
			}
		}
		return false
	}

	// === 2. 遍历全量日志 ===
	for _, rawLog := range logCache {
		// 复制一份 log 数据，避免修改原始缓存 (因为我们要修改 ProxyDetectResult 用于展示)
		log := rawLog 

		// --- A. 解析指纹元数据 ---
		var fp FingerprintMeta
		if log.FingerprintData != "" {
			_ = json.Unmarshal([]byte(log.FingerprintData), &fp)
		}

		// 归一化 Target
		currentPath := fp.Path
		if currentPath == "" { currentPath = fp.PathAlt }
		if currentPath == "" { currentPath = "Unknown" }

		// --- B. 收集选项 ---
		if currentPath != "Unknown" { optTargets[currentPath] = true }
		if fp.OS != ""              { optOS[fp.OS] = true }
		if fp.TimeZone != ""        { optTZ[fp.TimeZone] = true }
		if fp.Language != ""        { optLang[fp.Language] = true }

		// --- C. 核心修改：综合代理判定逻辑 ---
		// 逻辑：IP不一致 ? True : LatencyResult
		
		isProxy := false
		
		// 1. 检查 IP 是否不一致 (WebRTC IP vs Remote IP)
		// 只有当获取到了 WebRTC IPs 时才比较
		if len(log.IPs) > 0 {
			matchFound := false
			for _, webRTCIP := range log.IPs {
				if webRTCIP == log.RemoteIP {
					matchFound = true
					break
				}
			}
			// 如果 RemoteIP 不在 WebRTC IPs 列表中 -> 判定为代理
			if !matchFound {
				isProxy = true
			}
		}

		// 2. 如果 IP 一致 (或没拿到 WebRTC)，则回退使用延迟检测结果
		if !isProxy {
			// log.ProxyDetectResult 是字符串 "true"/"false"
			if log.ProxyDetectResult == "true" {
				isProxy = true
			}
		}

		// 3. 将计算后的最终结果赋值回去 (用于筛选 和 返回给前端展示)
		finalProxyStatus := strconv.FormatBool(isProxy) // "true" or "false"
		log.ProxyDetectResult = finalProxyStatus

		// --- D. 执行筛选逻辑 ---

		// 1. 代理筛选 (使用刚才计算出的 finalProxyStatus)
		if !matchExact(filterProxies, finalProxyStatus) {
			continue
		}

		// 2. Target 筛选
		if !matchExact(filterTargets, currentPath) {
			continue
		}

		// 3. Bot 筛选
		if !matchExact(filterBots, strconv.FormatBool(log.IsBot)) {
			continue
		}

		// 4. 时区筛选
		if !matchExact(filterTZ, fp.TimeZone) {
			continue
		}

		// 5. 语言筛选
		if !matchExact(filterLangs, fp.Language) {
			continue
		}

		// 6. 操作系统筛选 (模糊匹配)
		if len(filterOS) > 0 {
			osMatched := false
			for _, f := range filterOS {
				if strings.Contains(strings.ToLower(fp.OS), strings.ToLower(f)) {
					osMatched = true
					break
				}
			}
			if !osMatched { continue }
		}

		// --- E. 通过筛选，加入结果 ---
		filteredLogs = append(filteredLogs, log)
	}

	// === 3. 分页 ===
	total := len(filteredLogs)
	start := (page - 1) * size
	if start > total { start = total }
	end := start + size
	if end > total { end = total }

	pageData := filteredLogs[start:end]

	// === 4. 格式化选项 ===
	getKeys := func(m map[string]bool) []string {
		keys := make([]string, 0, len(m))
		for k := range m {
			if k != "" { keys = append(keys, k) }
		}
		return keys
	}

	// === 5. 返回 ===
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"code":  0,
		"total": total,
		"data":  pageData,
		"options": map[string][]string{
			"target":   getKeys(optTargets),
			"os":       getKeys(optOS),
			"timezone": getKeys(optTZ),
			"language": getKeys(optLang),
		},
	})
}

// getTargetIPsHandler 专门用于给 Python 中间件提供原始 IP 数据
func getTargetIPsHandler(w http.ResponseWriter, r *http.Request) {
    // 1. 基础检查
    if r.Method != http.MethodGet {
        http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
        return
    }

    // 2. 获取 target 参数
    targetParam := r.URL.Query().Get("target")
    if targetParam == "" {
        http.Error(w, "Target parameter is required", http.StatusBadRequest)
        return
    }

    // 3. 加读锁，准备遍历
    cacheMutex.RLock()
    defer cacheMutex.RUnlock()

    // 使用 Map 进行 IP 去重 (Set)
    uniqueIPs := make(map[string]bool)
    // 最终返回的切片
    resultIPs := make([]string, 0)

    // 4. 遍历内存中的全量日志
    for _, log := range logCache {
        
        // === A. 解析逻辑 (保持与列表页一致) ===
        // 我们需要确定这条日志到底属于哪个 Target
        currentTarget := "Unknown"

        // 优先从 FingerprintData 解析 path/Path
        if log.FingerprintData != "" {
            var fpData map[string]interface{}
            // 注意：这里忽略错误，解析失败就当没解析到
            if json.Unmarshal([]byte(log.FingerprintData), &fpData) == nil {
                if v, ok := fpData["path"].(string); ok {
                    currentTarget = v
                } else if v, ok := fpData["Path"].(string); ok {
                    currentTarget = v
                }
            }
        }


        // === B. 匹配逻辑 ===
        if currentTarget == targetParam {
            ip := log.RemoteIP
            
            // 过滤无效 IP 并去重
            if ip != "" && ip != "Unknown" && !uniqueIPs[ip] {
                uniqueIPs[ip] = true
                resultIPs = append(resultIPs, ip)
            }
        }
    }

    // 5. 返回 JSON 结果
    w.Header().Set("Content-Type", "application/json")
    json.NewEncoder(w).Encode(map[string]interface{}{
        "target": targetParam,
        "count":  len(resultIPs), // 返回 IP 总数方便调试
        "ips":    resultIPs,      // 核心数据：IP 字符串数组
    })
}



// 1. 定义 1x1 透明 GIF 的二进制数据
var pixelData = []byte{
	0x47, 0x49, 0x46, 0x38, 0x39, 0x61, 0x01, 0x00, 0x01, 0x00,
	0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0xff, 0xff, 0xff, 0x21,
	0xf9, 0x04, 0x01, 0x00, 0x00, 0x00, 0x00, 0x2c, 0x00, 0x00,
	0x00, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x02, 0x01, 0x44,
	0x00, 0x3b,
}

// 2. 新增处理 CSS 埋点请求的 Handler
func handlePixel(w http.ResponseWriter, r *http.Request) {
	// 使用你现有的工具函数获取 IP
	ip := getClientIP(r)
	ua := r.UserAgent()
	referer := r.Referer()
	if referer == "" {
		referer = "direct/unknown"
	}
	
	currentTime := time.Now().Format(time.RFC3339)

	// 记录日志：你可以选择复用 logUnified 逻辑，或者像 handleIPS 那样直接写文件
	// 这里为了简单直接，模仿 handleIPS 写入独立文件
	logLine := fmt.Sprintf("Time: %s | Type: CSS_TRACK | IP: %s | UA: %s | Ref: %s\n",
		currentTime, ip, ua, referer)
	
	// 写入专门的日志文件，方便区分
	appendToFile("log/css_track.log", logLine)
	
	// 在控制台打印，方便调试
	log.Printf("[CSS追踪] %s", logLine)

	// === 关键响应设置 ===
	w.Header().Set("Content-Type", "image/gif")
	// 禁止缓存，确保每次访问页面都触发请求
	w.Header().Set("Cache-Control", "no-cache, no-store, must-revalidate")
	w.Header().Set("Pragma", "no-cache")
	w.Header().Set("Expires", "0")

	// 返回 GIF 图片数据
	w.Write(pixelData)
}


// 1. 定义接收结构体 (对应 SSH 蜜罐发送的 JSON)
type SSHLogRequest struct {
	Msg           string `json:"msg"`
	Level         string `json:"level"`
	User          string `json:"duser"`          // 对应发送端的 duser
	Password      string `json:"password"`       // 对应发送端的 password
	Src           string `json:"src"`            // 对应发送端的 src (IP:Port)
	ClientVersion string `json:"client_version"` // 客户端版本
	Time          string `json:"time"`
}

// 2. 接收 SSH 日志的 Handler
func handleSSHLog(w http.ResponseWriter, r *http.Request) {
	// 允许跨域 (如果是本机互发其实不需要，但为了保险)
	enableCors(&w, r)
	if r.Method == http.MethodOptions {
		w.WriteHeader(http.StatusOK)
		return
	}

	var logData SSHLogRequest
	if err := json.NewDecoder(r.Body).Decode(&logData); err != nil {
		http.Error(w, "JSON 解析失败", http.StatusBadRequest)
		return
	}

	// 简单的过滤：只记录含有密码的尝试，或者你可以记录所有连接
	// 发送端的 msg 通常是 "Request with password"
	if logData.Password == "" && logData.Msg != "Request with password" {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("Ignored (No password)"))
		return
	}

	// 处理 IP (去掉端口号)
	ip := logData.Src
	if strings.Contains(ip, ":") {
		host, _, err := net.SplitHostPort(ip)
		if err == nil {
			ip = host
		}
	}

	// 入库
	stmt, err := db.Prepare(`
		INSERT INTO ssh_attacks (ip, username, password, client_version, raw_log, timestamp)
		VALUES (?, ?, ?, ?, ?, ?)
	`)
	if err != nil {
		log.Printf("SSH 入库 Prepare 失败: %v", err)
		http.Error(w, "DB Error", http.StatusInternalServerError)
		return
	}
	defer stmt.Close()

	// 存入数据库
	// raw_log 存一下原始 msg 备查
	timestamp := time.Now().Format(time.RFC3339)
	_, err = stmt.Exec(ip, logData.User, logData.Password, logData.ClientVersion, logData.Msg, timestamp)

	if err != nil {
		log.Printf("SSH 数据写入失败: %v", err)
	} else {
		log.Printf("🚨 [SSH蜜罐] 捕获攻击! IP:%s User:%s Pass:%s", ip, logData.User, logData.Password)
	}

	w.WriteHeader(http.StatusOK)
	w.Write([]byte("Logged"))
}

// 3. (可选) 提供一个接口给前端查询 SSH 攻击列表
func handleGetSSHLogs(w http.ResponseWriter, r *http.Request) {
	enableCors(&w, r)
	
	rows, err := db.Query("SELECT id, ip, username, password, client_version, timestamp FROM ssh_attacks ORDER BY id DESC LIMIT 50")
	if err != nil {
		http.Error(w, "DB Query Error", http.StatusInternalServerError)
		return
	}
	defer rows.Close()

	var logs []map[string]interface{}
	for rows.Next() {
		var id int
		var ip, user, pass, ver, ts string
		rows.Scan(&id, &ip, &user, &pass, &ver, &ts)
		
		logs = append(logs, map[string]interface{}{
			"id": id, "ip": ip, "username": user, "password": pass, "client": ver, "time": ts,
		})
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(logs)
}