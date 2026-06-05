package main

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"math"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/agnivade/levenshtein"
	"github.com/dlclark/regexp2"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"github.com/gorilla/websocket"
	"golang.org/x/net/icmp"
	"golang.org/x/net/ipv4"
)

// ================== 数据结构定义 ==================
type BotInfo struct {
	Name     string      `json:"name"`
	Category interface{} `json:"category"`
	URL      string      `json:"url,omitempty"`
	Producer *Producer   `json:"producer,omitempty"`
}

type Producer struct {
	Name string `json:"name"`
	URL  string `json:"url,omitempty"`
}

type BotRule struct {
	Name     string      `json:"name"`
	Regex    string      `json:"regex"`
	Category interface{} `json:"category"`
	URL      string      `json:"url,omitempty"`
	Producer *Producer   `json:"producer,omitempty"`
	compiled *regexp2.Regexp
}

type BotCheckRequest struct {
	SessionToken string  `json:"sessionToken"`
	UserAgent    string  `json:"userAgent"`
	MouseTrack   [][]int `json:"mouseTrack"` // [x, y]
	MouseMeta    struct {
		Timestamps []int64   `json:"timestamps"`
		Speeds     []float64 `json:"speeds"`
	} `json:"mouseMeta"`
	ClickIntervals []int64 `json:"clickIntervals"`
}

type MousePoint struct {
	X, Y         int     `json:"x"`
	T            int64   `json:"t"`
	Speed        float64 `json:"speed"`
	Acceleration float64 `json:"acceleration"`
}

type SessionInfo struct {
	LastUpdate time.Time
	Requests   []time.Time
	Score      int
	UA         string
	IP         string
}

type latency struct {
	WSRTT         float64 `json:"ws_rtt"`
	ICMPRTT       float64 `json:"icmp_rtt"`
	TCPRTT        float64 `json:"tcp_rtt"`
	TCPRTTReady   bool    `json:"-"`
	LatencyDiff   float64 `json:"latency_diff"`
	PossibleProxy bool    `json:"possible_proxy"`
	Timestamp     string  `json:"timestamp"`
}

type parasitism struct {
	Time                     string   `json:"time"`
	RemoteIP                 string   `json:"RemoteIP"`
	SessionToken             string   `json:"sessionToken"`
	ProxyDetectResult        string   `json:"ProxyDetectResult"`
	ProxyDetectResultDetails string   `json:"ProxyDetectResultdetails"`
	Ips                      []string `json:"IPs"`
	Path                     string   `json:"Path"`
	Fingerprint              string   `json:"Fingerprint"`
	FingerprintDetails       string   `json:"FingerprintDetails"`
}

type LogRecord struct {
	Time              string   `json:"time"`
	RemoteIP          string   `json:"RemoteIP"`
	IPs               []string `json:"IPs"`
	ProxyDetectResult string   `json:"ProxyDetectResult"`
	FingerprintData   string   `json:"FingerprintData"`
	Group_Id          int      `json:"group_id"`

	Score   int      `json:"score"`   // 评分
	IsBot   bool     `json:"isBot"`   // 是否判定为 Bot
	Reasons []string `json:"reasons"` // 判定理由 (数组)
}

// ================== 新增日志结构 ==================
type UnifiedLog struct {
	Base       *BaseLog      `json:"base,omitempty"`
	Detection  *DetectionLog `json:"detection,omitempty"`
	Abnormal   bool          `json:"abnormal,omitempty"`
	Standalone bool          `json:"standalone,omitempty"`
}

type BaseLog struct {
	Timestamp  string `json:"timestamp"`
	IP         string `json:"ip"`
	UserAgent  string `json:"userAgent"`
	RequestURL string `json:"requestUrl"`
	Method     string `json:"method"`
	Duration   string `json:"duration"`
	IsBot      bool   `json:"isBot"`
}

type DetectionLog struct {
	Timestamp    string   `json:"timestamp"`
	SessionID    string   `json:"sessionId,omitempty"`
	IP           string   `json:"ip"`
	Score        int      `json:"score"`
	MousePoints  int      `json:"mousePoints"`
	ClickCount   int      `json:"clickCount"`
	Reasons      []string `json:"reasons"`
	IsBot        bool     `json:"isBot"`
	RequestURL   string   `json:"requestUrl"`
	Method       string   `json:"method"`
	DetectMethod string   `json:"detectMethod"`
}

// ================== 全局变量 ==================
var (
	sessions = struct {
		sync.RWMutex
		data map[string]*SessionInfo
	}{data: make(map[string]*SessionInfo)}

	detector *BotDetector

	recentIPs = struct {
		sync.RWMutex
		data map[string]time.Time
	}{data: make(map[string]time.Time)}

	ipToSession = struct {
		sync.RWMutex
		data map[string]string
	}{data: make(map[string]string)}

	ipBaseLogs = struct {
		sync.RWMutex
		data map[string]*BaseLog
	}{data: make(map[string]*BaseLog)}

	pendingLogs = struct {
		sync.RWMutex
		data map[string]*BaseLog // key: IP地址
	}{data: make(map[string]*BaseLog)}

	logDelayDuration   = 10 * time.Second
	logCleanupInterval = 1 * time.Hour

	// 新增的全局变量
	logCache         []LogRecord
	cacheMutex       sync.RWMutex
	logFilePath      = filepath.Join("log", "total_log.json")
	connLatencyMap   map[string]*latency
	connLatencyMutex sync.RWMutex
	latencyLogFile   *os.File

	// nginx RTT 查询配置
	nginxRTTClient = &http.Client{Timeout: 2 * time.Second}
	nginxRTTServer = loadNginxRTTServer() // 从环境变量或 config.json 读取
)

var upgrader = websocket.Upgrader{
	CheckOrigin: func(r *http.Request) bool {
		return true
	},
}

const (
	BotScoreThreshold = 5
	CacheTTL          = 10 * time.Minute
	maxSize           = 10000000
	cleanupBatch      = 10000
)

// ================== 初始化函数 ==================
func setupLogger() {
	// 配置日志格式
	log.SetFlags(log.Ldate | log.Ltime | log.Lmicroseconds)
	log.SetPrefix("[Parasitic] ")

	// 可选：同时输出到文件和控制台
	logFile, err := os.OpenFile("log/console.log",
		os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0666)
	if err == nil {
		multiWriter := io.MultiWriter(os.Stdout, logFile)
		log.SetOutput(multiWriter)
	}
	log.Println("----------------------------------------------")

	err = os.MkdirAll("log", 0755)
	if err != nil {
		log.Println("创建 log 目录失败:", err)
		return
	}
}

func logUnified(logEntry UnifiedLog) {
	logBytes, err := json.Marshal(logEntry)
	if err != nil {
		log.Printf("Failed to marshal log entry: %v", err)
		return
	}

	// 追加到文件
	file, err := os.OpenFile("log/unified.log", os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		log.Printf("Failed to open log file: %v", err)
		return
	}
	defer file.Close()

	// 写入文件，每条日志一行
	if _, err := file.Write(append(logBytes, '\n')); err != nil {
		log.Printf("Failed to write log to file: %v", err)
	}

	// 同时输出到控制台
	log.Println(string(logBytes))

	if logEntry.Detection == nil {
		return
	}

	if db == nil {
		return
	}

	reasonsJSON, _ := json.Marshal(logEntry.Detection.Reasons)

	stmt, err := db.Prepare(`
		INSERT INTO bot_detections(session_token, ip, score, is_bot, reasons, timestamp) 
		VALUES(?, ?, ?, ?, ?, ?)
	`)
	if err == nil {
		defer stmt.Close()
		stmt.Exec(
			logEntry.Detection.SessionID,
			logEntry.Detection.IP,
			logEntry.Detection.Score,
			logEntry.Detection.IsBot,
			string(reasonsJSON),
			logEntry.Detection.Timestamp,
		)
	}
}

// ================== 网络相关函数 ==================
func getAllInterfaces() ([]string, error) {
	devices, err := pcap.FindAllDevs()
	if err != nil {
		return nil, fmt.Errorf("无法获取网卡列表: %v", err)
	}
	if len(devices) == 0 {
		return nil, fmt.Errorf("未找到可用网卡")
	}

	var names []string
	for _, device := range devices {
		// 跳过 down 状态的网卡
		if len(device.Addresses) == 0 {
			continue
		}
		names = append(names, device.Name)
	}

	if len(names) == 0 {
		return nil, fmt.Errorf("未找到可用网卡")
	}

	log.Printf("发现 %d 个可用网卡: %v", len(names), names)
	return names, nil
}

// func listenTCPHandshake(device, filter string) {
// 	handle, err := pcap.OpenLive(device, 1600, true, pcap.BlockForever)
// 	if err != nil {
// 		log.Fatal("Failed to open network interface:", err)
// 	}
// 	defer handle.Close()

// 	err = handle.SetBPFFilter(filter)
// 	if err != nil {
// 		log.Fatal("Failed to set BPF filter:", err)
// 	}

// 	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
// 	synAckTimes := make(map[string]time.Time)

// 	for packet := range packetSource.Packets() {
// 		tcpLayer := packet.Layer(layers.LayerTypeTCP)
// 		if tcpLayer == nil {
// 			continue
// 		}
// 		tcp, _ := tcpLayer.(*layers.TCP)
// 		ipLayer := packet.Layer(layers.LayerTypeIPv4)
// 		if ipLayer == nil {
// 			continue
// 		}
// 		ip, _ := ipLayer.(*layers.IPv4)
// 		connID := fmt.Sprintf("%s:%d -> %s:%d", ip.SrcIP, tcp.SrcPort, ip.DstIP, tcp.DstPort)

// 		if tcp.SYN && tcp.ACK {
// 			synAckTimes[connID] = packet.Metadata().Timestamp
// 		} else if tcp.ACK {
// 			if startTime, exists := synAckTimes[connID]; exists {
// 				rtt := float64(packet.Metadata().Timestamp.Sub(startTime).Milliseconds())
// 				id := ip.DstIP.String()
// 				if _, ok := connLatencyMap[id]; !ok {
// 					connLatencyMap[id] = &latency{}
// 				}
// 				if connLatencyMap[id].TCPRTT == 0 {
// 					connLatencyMap[id].TCPRTT = rtt
// 					//log.Printf("[TCP] Time: %v, RemoteIP: %s, RTT: %v\n", time.Now().Format(time.RFC3339), id, rtt)
// 				}
// 				delete(synAckTimes, connID)
// 			}
// 		}
// 	}
// }

// listenTCPHandshakeFixed 修复了方向 key 和客户端 IP 取反的问题
func listenTCPHandshake(device, filter string) {
	handle, err := pcap.OpenLive(device, 1600, true, pcap.BlockForever)
	if err != nil {
		log.Fatal("Failed to open network interface:", err)
	}
	defer handle.Close()

	err = handle.SetBPFFilter(filter)
	if err != nil {
		log.Fatal("Failed to set BPF filter:", err)
	}

	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	synAckTimes := make(map[string]time.Time)

	for packet := range packetSource.Packets() {
		tcpLayer := packet.Layer(layers.LayerTypeTCP)
		if tcpLayer == nil {
			continue
		}
		tcp, _ := tcpLayer.(*layers.TCP)
		ipLayer := packet.Layer(layers.LayerTypeIPv4)
		if ipLayer == nil {
			continue
		}
		ip, _ := ipLayer.(*layers.IPv4)
		connID := fmt.Sprintf("%s:%d -> %s:%d", ip.SrcIP, tcp.SrcPort, ip.DstIP, tcp.DstPort)

		if tcp.SYN && tcp.ACK {
			synAckTimes[connID] = packet.Metadata().Timestamp
		} else if tcp.ACK && !tcp.SYN {
			startTime, exists := synAckTimes[connID]
			if !exists {
				revConnID := fmt.Sprintf("%s:%d -> %s:%d", ip.DstIP, tcp.DstPort, ip.SrcIP, tcp.SrcPort)
				startTime, exists = synAckTimes[revConnID]
				if exists {
					connID = revConnID
				}
			}
			if exists {
				rtt := float64(packet.Metadata().Timestamp.Sub(startTime).Milliseconds())
				id := ip.SrcIP.String()
				connLatencyMutex.Lock()
				if _, ok := connLatencyMap[id]; !ok {
					connLatencyMap[id] = &latency{}
				}
				if !connLatencyMap[id].TCPRTTReady {
					connLatencyMap[id].TCPRTT = rtt
					connLatencyMap[id].TCPRTTReady = true
				}
				connLatencyMutex.Unlock()
				delete(synAckTimes, connID)
			}
		}
	}
}

func sendICMPPing(target string) (float64, error) {
	conn, err := icmp.ListenPacket("ip4:icmp", "0.0.0.0")
	if err != nil {
		return 0, err
	}
	defer conn.Close()

	dst, err := net.ResolveIPAddr("ip4", target)
	if err != nil {
		return 0, err
	}

	msg := icmp.Message{
		Type: ipv4.ICMPTypeEcho,
		Code: 0,
		Body: &icmp.Echo{
			ID:   1,
			Seq:  1,
			Data: []byte("ping"),
		},
	}
	msgBytes, err := msg.Marshal(nil)
	if err != nil {
		return 0, err
	}

	start := time.Now()
	_, err = conn.WriteTo(msgBytes, dst)
	if err != nil {
		return 0, err
	}

	reply := make([]byte, 1500)
	n, _, err := conn.ReadFrom(reply)
	if err != nil {
		return 0, err
	}

	elapsed := float64(time.Since(start))
	_, err = icmp.ParseMessage(1, reply[:n])
	if err != nil {
		return 0, err
	}

	return elapsed, nil
}

// ================== 辅助函数 ==================
func getCategoryName(category interface{}) string {
	switch v := category.(type) {
	case string:
		return v
	case int:
		categoryMap := map[int]string{
			0: "search_engine",
			1: "web_crawler",
			2: "security_scanner",
			3: "seo_tool",
			4: "monitoring",
			5: "analytics",
			6: "rss_reader",
			7: "social_media",
			8: "ai_bot",
			9: "miscellaneous",
		}
		if name, ok := categoryMap[v]; ok {
			return name
		}
		return fmt.Sprintf("category_%d", v)
	case float64:
		return getCategoryName(int(v))
	default:
		return "unknown"
	}
}

func abs(value float64) float64 {
	if value < 0 {
		return -value
	}
	return value
}

func enableCors(w *http.ResponseWriter, r *http.Request) {
	origin := r.Header.Get("Origin")
	if origin != "" {
		(*w).Header().Set("Access-Control-Allow-Origin", origin)
		(*w).Header().Set("Access-Control-Allow-Credentials", "true")
	}
	(*w).Header().Set("Access-Control-Allow-Methods", "POST, GET, OPTIONS, PUT, DELETE")
	(*w).Header().Set("Access-Control-Allow-Headers", "Content-Type, Access-Control-Allow-Headers, Authorization, X-Requested-With")
	(*w).Header().Set("Access-Control-Max-Age", "86400")
}

func getClientIP(r *http.Request) string {
	ip := r.Header.Get("X-Forwarded-For")
	if ip != "" {
		ips := strings.Split(ip, ",")
		if len(ips) > 0 {
			return strings.TrimSpace(ips[0])
		}
	}

	ip = r.Header.Get("X-Real-IP")
	if ip != "" {
		return ip
	}

	ip, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return ip
}

// func logLatency(id string) {
// 	diff := abs(connLatencyMap[id].WSRTT - connLatencyMap[id].TCPRTT)
// 	var res bool
// 	if diff >= 60 {
// 		res = true
// 	} else {
// 		res = false
// 	}
// 	connLatencyMap[id].LatencyDiff = diff
// 	connLatencyMap[id].PossibleProxy = res
// 	connLatencyMap[id].Timestamp = time.Now().Format(time.RFC3339)

// 	entry := connLatencyMap[id]
// 	logLine := fmt.Sprintf(
// 		"Time: %s, RemoteIP: %s, ProxyDetectResult: %v, details: %v,%v,%v\n",
// 		time.Now().Format(time.RFC3339),
// 		id,
// 		entry.PossibleProxy,
// 		entry.ICMPRTT,
// 		entry.TCPRTT,
// 		entry.WSRTT,
// 	)

// 	proxyDetectResultDetails := fmt.Sprintf(
// 		"%v,%v,%v",
// 		entry.ICMPRTT,
// 		entry.TCPRTT,
// 		entry.WSRTT,
// 	)

// 	if _, ok := dataMap[id]; !ok {
// 		dataMap[id] = &parasitism{}
// 	}
// 	dataMap[id].ProxyDetectResult = strconv.FormatBool(entry.PossibleProxy)
// 	dataMap[id].ProxyDetectResultDetails = proxyDetectResultDetails

// 	data := dataMap[id]
// 	log.Printf("🔍 [DEBUG DATA] ID: %s, Data内容: %+v", id, data)
// 	time.Sleep(3 * time.Second)
// 	SaveSingleRecord(*data, "log/total_log.json")

// 	if data.SessionToken == "" {
// 		log.Printf("[DB Warning] 无 SessionToken，跳过 IP: %s", id)
// 	}

// 	webrtcIPsJSON, _ := json.Marshal(data.Ips)

// 	stmt, err := db.Prepare(`
// 		INSERT INTO device_fingerprints (
// 			session_token, remote_ip, webrtc_ips, is_proxy, raw_json, timestamp
// 		) VALUES (?, ?, ?, ?, ?, ?)
// 	`)

// 	if err == nil {
// 		defer stmt.Close()
// 		stmt.Exec(
// 			data.SessionToken,       // 结构体直接取值
// 			id,
// 			string(webrtcIPsJSON),
// 			data.ProxyDetectResult,
// 			data.FingerprintDetails, // 原始大字符串
// 			entry.Timestamp,
// 		)
// 		log.Printf("[DB] 已存入 Session: %s", data.SessionToken)
// 	}

// 	// response, err := SendParasitismData(*data, serverURL)
// 	// if err != nil {
// 	// 	log.Printf("发送失败: %v", err)
// 	// } else {
// 	// 	log.Printf("发送成功! 服务器响应: %s", response)
// 	// }
// 	appendToFile("log/latency_log.log", logLine)
// 	log.Printf("[Latency] %s", logLine)
// }

func logLatency(id string) {
	// 1. 【安全检查】防止空指针 Panic
	connLatencyMutex.RLock()
	entry, exists := connLatencyMap[id]
	connLatencyMutex.RUnlock()
	if !exists || entry == nil {
		return // 没连上 WS，直接退出
	}

	diff := abs(entry.WSRTT - entry.TCPRTT)
	var res bool
	if diff >= 60 {
		res = true
	} else {
		res = false
	}

	// 更新 map
	connLatencyMutex.Lock()
	connLatencyMap[id].LatencyDiff = diff
	connLatencyMap[id].PossibleProxy = res
	connLatencyMap[id].Timestamp = time.Now().Format(time.RFC3339)
	connLatencyMutex.Unlock()

	proxyDetectResultDetails := fmt.Sprintf(
		"%v,%v,%v",
		entry.ICMPRTT,
		entry.TCPRTT,
		entry.WSRTT,
	)

	// 本地文件日志 (保留)
	logLine := fmt.Sprintf(
		"Time: %s, RemoteIP: %s, ProxyDetectResult: %v, details: %v\n",
		time.Now().Format(time.RFC3339), id, entry.PossibleProxy, proxyDetectResultDetails,
	)
	appendToFile("log/latency_log.log", logLine)
	log.Printf("[Latency] %s", logLine)

	// ==========================================
	// 🛠️ 修改部分：使用 SessionManager
	// ==========================================

	// 1. 获取 Buffer
	buf := sm.GetBuffer(id)

	// 2. 更新 WS 数据 (加锁)
	sm.mu.Lock()
	buf.Data.ProxyDetectResult = strconv.FormatBool(entry.PossibleProxy)
	buf.Data.ProxyDetectResultDetails = proxyDetectResultDetails
	// 补上时间
	buf.Data.Time = entry.Timestamp

	buf.IsWSReady = true // 🚩 标记 WS 就绪
	sm.mu.Unlock()

	// 3. 发送信号
	select {
	case sm.checkCh <- id:
	default:
	}

	// ❌ 已删除 time.Sleep(3 * time.Second)
	// ❌ 已删除 SaveSingleRecord
	// ❌ 已删除 db.Prepare / stmt.Exec (移至 session_manager.go)
}

func appendToFile(filename, content string) error {
	file, err := os.OpenFile(filename, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		return err
	}
	defer file.Close()

	_, err = file.WriteString(content)
	return err
}

// getRTTFromNginx 从 nginx 服务器上的抓包服务查询客户端 TCP RTT
func getRTTFromNginx(ip string) (float64, error) {
	url := nginxRTTServer + "/rtt?ip=" + ip
	resp, err := nginxRTTClient.Get(url)
	if err != nil {
		log.Printf("[RTT] 请求失败 %s: %v", url, err)
		return 0, err
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNotFound {
		log.Printf("[RTT] %s 返回 404", url)
		return 0, fmt.Errorf("rtt not found")
	}

	var rtt float64
	_, err = fmt.Fscanf(resp.Body, "%f", &rtt)
	if err != nil {
		log.Printf("[RTT] 解析失败 %s: %v", url, err)
	}
	return rtt, err
}

func waitForTCPRTT(ip string, timeout time.Duration) float64 {
	interval := 20 * time.Millisecond
	deadline := time.Now().Add(timeout)

	for time.Now().Before(deadline) {
		if rtt, err := getRTTFromNginx(ip); err == nil && rtt >= 0 {
			log.Printf("[RTT] 从 nginx 获取到 %s 的 RTT: %.2fms", ip, rtt)

			// 写回本地缓存，logLatency 会从这里读
			connLatencyMutex.Lock()
			if _, ok := connLatencyMap[ip]; !ok {
				connLatencyMap[ip] = &latency{}
			}
			connLatencyMap[ip].TCPRTT = rtt
			connLatencyMap[ip].TCPRTTReady = true
			connLatencyMutex.Unlock()

			return rtt
		}
		time.Sleep(interval)
	}

	log.Printf("[RTT] 获取 %s 的 RTT 超时", ip)
	return 0
}

func SaveSingleRecord(data parasitism, filename string) error {
	filtered := struct {
		Time            string   `json:"time"`
		RemoteIP        string   `json:"RemoteIP"`
		Ips             []string `json:"IPs"`
		Proxy           string   `json:"ProxyDetectResult"`
		FingerprintData string   `json:"FingerprintData"`
	}{
		Time:            data.Time,
		RemoteIP:        data.RemoteIP,
		Ips:             data.Ips,
		Proxy:           data.ProxyDetectResult,
		FingerprintData: data.FingerprintDetails,
	}

	jsonData, err := json.Marshal(filtered)
	if err != nil {
		return fmt.Errorf("JSON编码失败: %v", err)
	}

	file, err := os.OpenFile(filename, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		return fmt.Errorf("文件打开失败: %v", err)
	}
	defer file.Close()

	if _, err := file.Write(append(jsonData, '\n')); err != nil {
		return fmt.Errorf("文件写入失败: %v", err)
	}

	return nil
}

// 从文件读
func reloadLogCache1() {
	for {
		file, err := os.ReadFile(logFilePath)
		if err != nil {
			log.Printf("读取日志文件失败: %v", err)
			time.Sleep(5 * time.Second)
			continue
		}

		var logs []LogRecord
		for _, line := range strings.Split(string(file), "\n") {
			line = strings.TrimSpace(line)
			if line == "" {
				continue
			}

			var record LogRecord
			if err := json.Unmarshal([]byte(line), &record); err == nil {
				logs = append(logs, record)
			}
		}

		cacheMutex.Lock()
		logCache = logs
		cacheMutex.Unlock()

		time.Sleep(30 * time.Second)
	}
}

//从数据库读
// 修改 utils.go 中的 reloadLogCache

func reloadLogCache() {
	for {
		if db == nil {
			cacheMutex.Lock()
			logCache = nil
			cacheMutex.Unlock()
			time.Sleep(10 * time.Second)
			continue
		}

		// 使用 LEFT JOIN 关联两个表
		// d = device_fingerprints (主表)
		// b = bot_detections (副表)
		query := `
			SELECT 
				d.timestamp, 
				d.remote_ip, 
				d.webrtc_ips, 
				d.is_proxy, 
				d.raw_json,
				d.group_id,
				b.score,
				b.is_bot,
				b.reasons
			FROM device_fingerprints d
			LEFT JOIN bot_detections b ON d.session_token = b.session_token
			ORDER BY d.id DESC
		`

		rows, err := db.Query(query)
		if err != nil {
			log.Printf("[Cache] DB Error: %v", err)
			time.Sleep(30 * time.Second)
			continue
		}

		var tempLogs []LogRecord

		for rows.Next() {
			var rec LogRecord
			var webrtcIPsString string

			// 定义 Null 类型变量，用于接收可能为空的 Bot 字段
			var score sql.NullInt64
			var isBot sql.NullBool
			var reasonsString sql.NullString

			// 扫描数据
			err := rows.Scan(
				&rec.Time,
				&rec.RemoteIP,
				&webrtcIPsString,
				&rec.ProxyDetectResult,
				&rec.FingerprintData,
				&rec.Group_Id,
				&score,         // 接收 Score (可能为 NULL)
				&isBot,         // 接收 IsBot (可能为 NULL)
				&reasonsString, // 接收 Reasons (可能为 NULL)
			)
			if err != nil {
				log.Printf("[Cache] Scan Error: %v", err)
				continue
			}

			// 1. 处理 WebRTC IPs (JSON String -> Slice)
			if webrtcIPsString != "" {
				_ = json.Unmarshal([]byte(webrtcIPsString), &rec.IPs)
			} else {
				rec.IPs = []string{}
			}

			// 2. 处理 Bot 数据 (检查是否 Valid)
			if score.Valid {
				rec.Score = int(score.Int64)
			} else {
				rec.Score = 0 // 默认为 0
			}

			if isBot.Valid {
				rec.IsBot = isBot.Bool
			} else {
				rec.IsBot = false // 默认为 false
			}

			// 3. 处理 Reasons (JSON String -> Slice)
			if reasonsString.Valid && reasonsString.String != "" {
				_ = json.Unmarshal([]byte(reasonsString.String), &rec.Reasons)
			} else {
				rec.Reasons = []string{} // 默认为空数组
			}

			tempLogs = append(tempLogs, rec)
		}
		rows.Close()

		// 更新内存缓存
		cacheMutex.Lock()
		logCache = tempLogs
		cacheMutex.Unlock()

		// log.Printf("[Cache] 缓存已刷新，包含关联 Bot 数据，共 %d 条", len(logCache))
		time.Sleep(10 * time.Second)
	}
}

func combineMouseTrackWithT(data BotCheckRequest) [][]int64 {
	track := [][]int64{}
	minLen := len(data.MouseTrack)
	if len(data.MouseMeta.Timestamps) < minLen {
		minLen = len(data.MouseMeta.Timestamps)
	}

	for i := 0; i < minLen; i++ {
		x := int64(data.MouseTrack[i][0])
		y := int64(data.MouseTrack[i][1])
		t := data.MouseMeta.Timestamps[i]
		track = append(track, []int64{x, y, t})
	}
	return track
}

// ================== 行为分析函数 ==================
func calculateVariances(track []MousePoint) (accelVariance, speedVariance float64) {
	if len(track) < 2 {
		return 0, 0
	}

	var accelSum, accelSqSum, speedSum, speedSqSum float64
	n := float64(len(track))

	for _, p := range track {
		accelSum += p.Acceleration
		accelSqSum += p.Acceleration * p.Acceleration
		speedSum += p.Speed
		speedSqSum += p.Speed * p.Speed
	}

	accelMean := accelSum / n
	speedMean := speedSum / n

	return accelSqSum/n - accelMean*accelMean, speedSqSum/n - speedMean*speedMean
}

func calculateClickVariance(intervals []int64) float64 {
	if len(intervals) < 2 {
		return 0
	}

	var sum, sumSq float64
	n := float64(len(intervals))

	for _, v := range intervals {
		val := float64(v)
		sum += val
		sumSq += val * val
	}

	mean := sum / n
	return sumSq/n - mean*mean
}

func analyzeRequestFrequency(requests []time.Time) int {
	if len(requests) < 2 {
		return 0
	}

	var intervals []float64
	for i := 1; i < len(requests); i++ {
		interval := requests[i].Sub(requests[i-1]).Seconds()
		intervals = append(intervals, interval)
	}

	var sum, sumSq float64
	for _, interval := range intervals {
		sum += interval
		sumSq += interval * interval
	}

	mean := sum / float64(len(intervals))
	variance := sumSq/float64(len(intervals)) - mean*mean

	if variance < 0.1 {
		return 2
	}
	return 0
}

func calcScore(s *SessionInfo, mouseTrack [][]int64, clickIntervals []int64) int {
	score := 0
	log.Printf("===== 开始检测会话 %s (IP: %s) =====\n", s.IP, s.UA)

	// 记录判断依据
	var reasons []string

	// 1. UA检测
	if detector.IsBot(s.UA) {
		// Headless UA直接判定Bot
		score += 3
		reason := fmt.Sprintf("UA匹配Bot规则 (得分+3) → %s", s.UA)
		reasons = append(reasons, reason)
		log.Println("[UA检测]", reason)

		if botInfo, ok := detector.Parse(s.UA); ok {
			log.Printf("[UA解析] 识别为 %s (分类: %v)\n",
				botInfo.Name, getCategoryName(botInfo.Category))
		}
	} else {
		log.Printf("[UA检测] 正常UA: %s\n", s.UA)
	}

	// 2. 鼠标轨迹分析
	if len(mouseTrack) < 5 {
		score += 2 // 放宽得分
		reason := fmt.Sprintf("鼠标轨迹点过少 (%d < 5) (得分+2)", len(mouseTrack))
		reasons = append(reasons, reason)
		log.Println("[行为检测]", reason)
	} else {
		if isRegularMouseTrack(mouseTrack) {
			score += 3
			reason := "鼠标轨迹过于规律 (得分+3)"
			reasons = append(reasons, reason)
			log.Println("[行为检测]", reason)
		}
	}

	// 3. 点击间隔分析
	if len(clickIntervals) > 1 {
		variance := calculateClickVariance(clickIntervals)
		log.Printf("[行为检测] 点击间隔方差: %.2fms\n", variance)

		if variance < 1000 { // 放宽阈值
			score += 3
			reason := fmt.Sprintf("点击间隔过于规律 (方差=%.2f) (得分+3)", variance)
			reasons = append(reasons, reason)
			log.Println("[行为检测]", reason)
		}
	} else if len(clickIntervals) == 0 {
		score += 1
		reason := "无点击事件记录 (得分+1)"
		reasons = append(reasons, reason)
		log.Println("[行为检测]", reason)
	}

	// 4. 请求频率检测
	if len(s.Requests) > 2 { // 放宽要求
		freqScore := analyzeRequestFrequency(s.Requests)
		if freqScore > 0 {
			score += freqScore
			reason := fmt.Sprintf("请求频率异常 (得分+%d)", freqScore)
			reasons = append(reasons, reason)
			log.Println("[请求分析]", reason)
		}
	}

	log.Printf("===== 检测结束 总分: %d =====\n", score)
	if len(reasons) > 0 {
		log.Println("【Bot判断依据】")
		for _, r := range reasons {
			log.Printf("  - %s", r)
		}
	} else {
		log.Println("【Bot判断依据】无异常行为，判定为正常用户")
	}

	// 强制判定 Headless UA 为 Bot
	if strings.Contains(strings.ToLower(s.UA), "headlesschrome") {
		score = BotScoreThreshold
		log.Println("⚠️ 强制判定 HeadlessChrome 为 Bot")
	}

	return score
}

// 新增辅助函数
// 替换掉旧的 isRegularMouseTrack 函数，使用这个改进版
func isRegularMouseTrack(track [][]int64) bool {
	n := len(track)
	if n < 6 {
		log.Printf("[MouseTrack] 太短的轨迹: %d 个点", n)
		return false
	}

	// 提取浮动数值
	xs := make([]float64, n)
	ys := make([]float64, n)
	ts := make([]float64, n) // 秒
	for i := 0; i < n; i++ {
		xs[i] = float64(track[i][0])
		ys[i] = float64(track[i][1])
		ts[i] = float64(track[i][2]) / 1000.0
	}

	// 计算 dt, dist, 原始速度
	dts := make([]float64, n-1)
	dists := make([]float64, n-1)
	speeds := make([]float64, n-1)
	for i := 1; i < n; i++ {
		dt := ts[i] - ts[i-1]
		if dt <= 0 {
			dt = 0.01
		}
		dts[i-1] = dt
		dx := xs[i] - xs[i-1]
		dy := ys[i] - ys[i-1]
		dist := math.Hypot(dx, dy)
		dists[i-1] = dist
		speeds[i-1] = dist / dt // px / s
	}

	// 使用小的滑动平均平滑位置和速度，以模拟连续曲线
	smoothX := movingAverageFloat64(xs, 3)
	smoothY := movingAverageFloat64(ys, 3)
	smoothSpeeds := movingAverageFloat64(speeds, 3)

	// 计算方向（角度）和转弯角度（角度变化）
	dirs := []float64{}
	for i := 1; i < n; i++ {
		dx := smoothX[i] - smoothX[i-1]
		dy := smoothY[i] - smoothY[i-1]
		ang := math.Atan2(dy, dx) * 180.0 / math.Pi
		dirs = append(dirs, ang)
	}
	turns := []float64{} // 角度变化
	for i := 1; i < len(dirs); i++ {
		da := normalizeAngle(dirs[i] - dirs[i-1]) // -180..180
		turns = append(turns, da)
	}

	// 曲率：abs(转弯角度) / 步长距离（避免除0）
	curvatures := []float64{}
	for i := 1; i < len(dists); i++ {
		dist := dists[i]
		if dist < 1e-6 {
			dist = 1.0
		}
		curv := math.Abs(turns[i-1]) / dist // 每像素度数
		curvatures = append(curvatures, curv)
	}

	// 计算加速度（从平滑后的速度计算）
	accs := []float64{}
	for i := 1; i < len(smoothSpeeds); i++ {
		dt := dts[i]
		if dt <= 0 {
			dt = 0.01
		}
		acc := (smoothSpeeds[i] - smoothSpeeds[i-1]) / dt // px/s^2
		accs = append(accs, acc)
	}

	// 特征计算
	pauseCount := 0
	for _, dist := range dists {
		if dist < 1.0 {
			pauseCount++
		}
	}
	pauseRatio := float64(pauseCount) / float64(len(dists))

	meanAbsTurn := meanAbs(turns)
	turnVar := variance(turns, mean(turns))
	curvVar := variance(curvatures, mean(curvatures))
	accelVar := varianceFloat64(accs)
	speedVar := varianceFloat64(smoothSpeeds)
	speedAC1 := autocorrLag1(smoothSpeeds)

	// 日志诊断信息
	log.Printf("[MouseTrack] 点数=%d, pauseRatio=%.3f, meanAbsTurn=%.3fdeg, turnVar=%.3f, curvVar=%.6f, accelVar=%.3f, speedVar=%.3f, speedAC1=%.3f",
		n, pauseRatio, meanAbsTurn, turnVar, curvVar, accelVar, speedVar, speedAC1)

	// 针对 "机械/规律" 特征进行打分（分数越高越像 Bot）
	botScore := 0

	// 1) 太少停顿 -> +1
	if pauseRatio < 0.05 {
		botScore += 1
	}

	// 2) 方向变化太小（近直线） -> +2
	if meanAbsTurn < 7.5 { // 平均转角 < 8度 很像直线
		botScore += 2
	}

	// 3) 方向变化方差非常小（持续直线） -> +2
	if turnVar < 10.0 {
		botScore += 2
	}

	// 4) 曲率方差小（缺少曲线行为） -> +2
	if curvVar < 0.45 {
		botScore += 2
	}

	// 5) 加速度方差极小（匀速） -> +2
	if accelVar < 180.0 {
		botScore += 2
	}

	// 6) 速度自相关非常高（非常规律） -> +1
	if speedAC1 > 0.93 {
		botScore += 1
	}

	log.Printf("[MouseTrack] 机械性评分(botScore) = %d (>=4 表示较规律/可疑)", botScore)

	// 判定阈值：botScore >= 4 判定为规律轨迹 (可调)
	return botScore >= 43
}

// ---------------- 辅助函数 ----------------

// movingAverageFloat64: 简单的中心滑动平均（窗口大小为奇数）
func movingAverageFloat64(arr []float64, window int) []float64 {
	if window <= 1 {
		out := make([]float64, len(arr))
		copy(out, arr)
		return out
	}
	n := len(arr)
	out := make([]float64, n)
	half := window / 2
	for i := 0; i < n; i++ {
		sum := 0.0
		cnt := 0
		for j := i - half; j <= i+half; j++ {
			if j >= 0 && j < n {
				sum += arr[j]
				cnt++
			}
		}
		if cnt > 0 {
			out[i] = sum / float64(cnt)
		} else {
			out[i] = arr[i]
		}
	}
	return out
}

// normalizeAngle：将角度规范化为 [-180, 180]
func normalizeAngle(a float64) float64 {
	for a <= -180 {
		a += 360
	}
	for a > 180 {
		a -= 360
	}
	return a
}

// mean：计算平均值
func mean(arr []float64) float64 {
	if len(arr) == 0 {
		return 0
	}
	s := 0.0
	for _, v := range arr {
		s += v
	}
	return s / float64(len(arr))
}

// meanAbs：计算绝对值的平均值
func meanAbs(arr []float64) float64 {
	if len(arr) == 0 {
		return 0
	}
	s := 0.0
	for _, v := range arr {
		s += math.Abs(v)
	}
	return s / float64(len(arr))
}

// variance：计算方差
func variance(arr []float64, m float64) float64 {
	if len(arr) == 0 {
		return 0
	}
	s := 0.0
	for _, v := range arr {
		d := v - m
		s += d * d
	}
	return s / float64(len(arr))
}

// varianceFloat64：计算浮动数值数组的方差
func varianceFloat64(arr []float64) float64 {
	if len(arr) == 0 {
		return 0
	}
	m := mean(arr)
	return variance(arr, m)
}

// autocorrLag1：计算滞后1的自相关（返回值范围[-1, 1]）
func autocorrLag1(arr []float64) float64 {
	n := len(arr)
	if n < 3 {
		return 0
	}
	m := mean(arr)
	num := 0.0
	den := 0.0
	for i := 0; i < n-1; i++ {
		num += (arr[i] - m) * (arr[i+1] - m)
	}
	for i := 0; i < n; i++ {
		den += (arr[i] - m) * (arr[i] - m)
	}
	if den == 0 {
		return 0
	}
	return num / den
}

// ================== ✅ 向量相似度与缓存逻辑 ==================

const SimilarityThreshold = 0.85

// 1. 硬件向量定义 (适配前端特殊拼写和字符串格式)
type HardwareVectors struct {
	Cpu      string      `json:"cpu"`
	CpuCores interface{} `json:"cpuCores"`

	GpuInfo struct {
		Renderer string `json:"renderer"`
		Vendor   string `json:"vendor"`
	} `json:"gpuInfo"`

	Os        string `json:"os"`
	OsVersion string `json:"osVersion"`
	Language  string `json:"language"`
	TimeZone  string `json:"timeZone"`

	ScreenPrint string `json:"screenPrint"`

	// DrawnApart 字段（双重兼容）
	DrawnApartTrace  []float64 `json:"drawnApartTrace"`
	Trace            []float64 `json:"trace"` // 兼容 proxydetect 前端旧字段名
	DrawnApartMethod string    `json:"drawnApartMethod"`
}

// 2. 内存缓存
type GroupCacheItem struct {
	ID     int
	Vector HardwareVectors
}

var groupCache = struct {
	sync.RWMutex
	items []GroupCacheItem
}{items: make([]GroupCacheItem, 0)}

// 3. 加载缓存
func LoadFingerprintCache() {
	log.Println("🔄 [Cache] 正在加载指纹组缓存...")
	if db == nil {
		log.Println("⚠️ [Cache] DB disabled, skip cache load")
		return
	}
	rows, err := db.Query("SELECT id, vector_json FROM fingerprint_groups")
	if err != nil {
		log.Printf("⚠️ [Cache] 加载失败: %v", err)
		return
	}
	defer rows.Close()

	groupCache.Lock()
	defer groupCache.Unlock()
	groupCache.items = make([]GroupCacheItem, 0)

	count := 0
	for rows.Next() {
		var id int
		var vecStr string
		if err := rows.Scan(&id, &vecStr); err != nil {
			continue
		}
		var vec HardwareVectors
		if err := json.Unmarshal([]byte(vecStr), &vec); err == nil {
			groupCache.items = append(groupCache.items, GroupCacheItem{ID: id, Vector: vec})
			count++
		}
	}
	log.Printf("✅ [Cache] 加载完成，共 %d 个指纹组", count)
}

// 4. 获取 GroupID (核心入口)
func GetOrCreateGroupID(rawJSON string) int {
	if db == nil {
		return 0
	}

	var newVec HardwareVectors
	if err := json.Unmarshal([]byte(rawJSON), &newVec); err != nil {
		log.Printf("[Group] JSON 解析失败: %v", err)
		return 0
	}

	// 兼容 fallback：如果旧前端只发了 "trace"，把它复制到 "drawnApartTrace"
	if len(newVec.DrawnApartTrace) == 0 && len(newVec.Trace) > 0 {
		newVec.DrawnApartTrace = newVec.Trace
	}

	bestScore := 0.0
	bestID := 0

	groupCache.RLock()
	for _, item := range groupCache.items {
		score := calculateSimilarity(newVec, item.Vector)
		if score > bestScore {
			bestScore = score
			bestID = item.ID
		}
	}
	groupCache.RUnlock()

	if bestScore >= SimilarityThreshold {
		log.Printf("🔍 [Group] 匹配旧设备 ID:%d (相似度:%.1f%%)", bestID, bestScore*100)
		return bestID
	}

	log.Printf("🆕 [Group] 创建新设备组 (最高分:%.1f%%)", bestScore*100)
	vecBytes, _ := json.Marshal(newVec)

	res, err := db.Exec("INSERT INTO fingerprint_groups (vector_json, created_at) VALUES (?, ?)",
		string(vecBytes), time.Now().Format(time.RFC3339))
	if err != nil {
		return 0
	}
	newID, _ := res.LastInsertId()

	groupCache.Lock()
	groupCache.items = append(groupCache.items, GroupCacheItem{ID: int(newID), Vector: newVec})
	groupCache.Unlock()

	return int(newID)
}

// isValidTrace 检查 trace 是否为有效的高精度 GPU 计时数据
// Firefox 等浏览器可能返回全为 1~5 毫秒的低精度数据，需要过滤掉
func isValidTrace(trace []float64) bool {
	if len(trace) == 0 {
		return false
	}
	maxVal := 0.0
	sum := 0.0
	for _, v := range trace {
		if v > maxVal {
			maxVal = v
		}
		sum += v
	}
	avg := sum / float64(len(trace))

	variance := 0.0
	for _, v := range trace {
		diff := v - avg
		variance += diff * diff
	}
	variance /= float64(len(trace))

	// Firefox 特征：值很小(<10)且方差极小(<0.5)，视为无效数据
	if maxVal < 10 && variance < 0.5 {
		return false
	}
	return true
}

func computeTraceSimilarity(a, b []float64) float64 {
	if len(a) != len(b) || len(a) == 0 {
		return 0.0
	}
	var dotProduct, normA, normB float64
	for i := 0; i < len(a); i++ {
		dotProduct += a[i] * b[i]
		normA += a[i] * a[i]
		normB += b[i] * b[i]
	}
	if normA == 0 || normB == 0 {
		return 0.0
	}
	return dotProduct / (math.Sqrt(normA) * math.Sqrt(normB))
}

func getDrawnApartTrace(v HardwareVectors) []float64 {
	if len(v.DrawnApartTrace) > 0 {
		return v.DrawnApartTrace
	}
	return v.Trace
}

func calculateSimilarity(v1, v2 HardwareVectors) float64 {
	score := 0.0
	totalWeight := 0.0

	// ==================================================
	// 核心硬指标 (High Entropy) - 权重 60%
	// 这些特征如果不同，几乎肯定是不同设备
	// ==================================================

	// 1. CPU 核心数 (权重 20) - 必须完全一致
	cpuWeight := 20.0
	totalWeight += cpuWeight
	if fmt.Sprintf("%v", v1.CpuCores) == fmt.Sprintf("%v", v2.CpuCores) {
		score += cpuWeight
	}

	// 2. 屏幕解析 (解析字符串后比对)
	s1 := parseScreenString(v1.ScreenPrint)
	s2 := parseScreenString(v2.ScreenPrint)

	// 当前分辨率 (权重 20) - 必须完全一致
	resWeight := 20.0
	totalWeight += resWeight
	if s1["Current Resolution"] == s2["Current Resolution"] && s1["Current Resolution"] != "" {
		score += resWeight
	}

	// 显卡渲染器 (权重 20) - 使用 Power 函数放大差异
	gpuWeight := 20.0
	totalWeight += gpuWeight
	gpuSim := stringSim(v1.GpuInfo.Renderer, v2.GpuInfo.Renderer)
	score += math.Pow(gpuSim, 3) * gpuWeight

	// ==================================================
	// 辅助硬指标 (Medium Entropy) - 权重 20%
	// ==================================================

	// 可用分辨率 (权重 10) - 排除任务栏后的分辨率
	availResWeight := 10.0
	totalWeight += availResWeight
	if s1["Available Resolution"] == s2["Available Resolution"] && s1["Available Resolution"] != "" {
		score += availResWeight
	}

	// 操作系统详细版本 (权重 10)
	osVerWeight := 10.0
	totalWeight += osVerWeight
	score += stringSim(v1.OsVersion, v2.OsVersion) * osVerWeight

	// ==================================================
	// 基础环境 (Low Entropy) - 权重 20%
	// 这些特征重复率极高 (Win10, zh-CN, Timezone)，权重必须低
	// ==================================================

	miscWeight := 20.0
	totalWeight += miscWeight
	miscScore := 0.0

	// 以下 5 项每项占 miscWeight 的 1/5 (即 4分)
	if v1.Os == v2.Os {
		miscScore += 0.2
	}
	if v1.Language == v2.Language {
		miscScore += 0.2
	}
	if v1.TimeZone == v2.TimeZone {
		miscScore += 0.2
	}
	if v1.GpuInfo.Vendor == v2.GpuInfo.Vendor {
		miscScore += 0.2
	}
	if s1["Color Depth"] == s2["Color Depth"] {
		miscScore += 0.2
	}

	score += miscScore * miscWeight

	// ==================================================
	// DrawnApart GPU 指纹 (最高置信度) - 动态权重
	// ==================================================
	t1 := getDrawnApartTrace(v1)
	t2 := getDrawnApartTrace(v2)
	hasDA := len(t1) > 0 && len(t2) > 0 && len(t1) == len(t2) && isValidTrace(t1) && isValidTrace(t2)

	if hasDA {
		daSim := computeTraceSimilarity(t1, t2)
		// DrawnApart 权重 25：
		// 如果 trace 高度相似(>0.85)，这是一个极强的同一设备信号
		// 如果 trace 不相似，也不应强行拉低总分（避免误杀正常用户换浏览器）
		// 所以用 daSim^2 来放大高相似度的优势，同时不过度惩罚低相似度
		daWeight := 25.0
		totalWeight += daWeight
		score += math.Pow(daSim, 2) * daWeight

		log.Printf("[DrawnApart] traceSim=%.4f, len=%d", daSim, len(t1))
	}

	if totalWeight == 0 {
		return 0
	}
	return score / totalWeight
}

// 辅助：解析 "Key: Val, Key2: Val2"
func parseScreenString(info string) map[string]string {
	result := make(map[string]string)
	parts := strings.Split(info, ",")
	for _, part := range parts {
		kv := strings.Split(strings.TrimSpace(part), ":")
		if len(kv) >= 2 {
			result[strings.TrimSpace(kv[0])] = strings.TrimSpace(kv[1])
		}
	}
	return result
}

func stringSim(s1, s2 string) float64 {
	if s1 == "" || s2 == "" {
		if s1 == s2 {
			return 1.0
		}
		return 0.0
	}
	dist := levenshtein.ComputeDistance(s1, s2)
	maxLen := math.Max(float64(len(s1)), float64(len(s2)))
	if maxLen == 0 {
		return 1.0
	}
	return 1.0 - (float64(dist) / maxLen)
}

// 在 utils.go 的全局变量区域添加（或者放在函数上面）
var (
	// 记录 IP 的冷却时间
	// Key: IP字符串, Value: time.Time (冷却结束时间)
	honeypotCooldown sync.Map
)

// 修改 RecordHoneypotHit 函数
func RecordHoneypotHit(ip, path, ua string) {
	// === 1. 防爆破检测 (Rate Limiting) ===
	// 检查该 IP 是否还在冷却期内
	if expiry, ok := honeypotCooldown.Load(ip); ok {
		// 如果当前时间还在冷却结束时间之前，说明是重复攻击
		if time.Now().Before(expiry.(time.Time)) {
			// 直接忽略，不写日志，不查库
			// (控制台也不要打印了，否则控制台也会被刷屏)
			return
		}
	}

	// === 2. 设置冷却时间 ===
	// 设定 5 分钟内，同一个 IP 不再重复记录
	// 你可以根据需要调整这个时间，比如 1 * time.Hour
	honeypotCooldown.Store(ip, time.Now().Add(5*time.Minute))

	// === 3. 启动一个清理协程 (可选，防止内存泄露) ===
	// 如果你不介意内存，可以不加这个。但在高并发下建议加上。
	// 更好的做法是在 main.go 里有一个全局清理定时器，这里为了简单演示用 time.AfterFunc
	time.AfterFunc(5*time.Minute, func() {
		honeypotCooldown.Delete(ip)
	})

	// === 4. 原有的记录逻辑 (保持不变) ===
	timestamp := time.Now().Format(time.RFC3339)

	// 写文件
	logContent := fmt.Sprintf("Time: %s | IP: %s | Path: %s | UA: %s\n", timestamp, ip, path, ua)
	appendToFile("log/honeypot.log", logContent)

	if db == nil {
		return
	}

	// 入库
	stmt, err := db.Prepare("INSERT INTO honeypot_events(ip, trap_path, user_agent, timestamp) VALUES(?, ?, ?, ?)")
	if err != nil {
		log.Printf("蜜罐数据库 Prepare 失败: %v", err)
		return
	}
	defer stmt.Close()

	_, err = stmt.Exec(ip, path, ua, timestamp)
	if err != nil {
		log.Printf("蜜罐数据入库失败: %v", err)
	} else {
		log.Printf("🔨 [蜜罐] 新增攻击记录: %s -> %s (已启动5分钟冷却防刷)", ip, path)
	}
}

// CheckScanHistory 检查该 IP 在过去 24 小时内是否有扫描记录
// CheckScanHistory 检查该 IP 在过去 24 小时内所有的扫描记录
// 返回值: (是否有记录, 汇总后的描述字符串)
func CheckScanHistory(ip string) (bool, string) {
	// 1. 设定回溯时间窗口：24小时
	timeWindow := time.Now().Add(-24 * time.Hour).Format(time.RFC3339)

	// 2. 查询该 IP 在这段时间内的【所有】记录 (去掉了 LIMIT 1)
	query := `
		SELECT trap_path, timestamp 
		FROM honeypot_events 
		WHERE ip = ? AND timestamp > ? 
		ORDER BY id DESC
	`

	if db == nil {
		return false, ""
	}

	rows, err := db.Query(query, ip, timeWindow)
	if err != nil {
		return false, ""
	}
	defer rows.Close()

	// 3. 汇总逻辑
	var paths []string
	var uniqueMap = make(map[string]bool) // 用于去重
	var firstTime string
	count := 0

	for rows.Next() {
		var p, t string
		if err := rows.Scan(&p, &t); err != nil {
			continue
		}

		// 记录最近一次的时间
		if firstTime == "" {
			firstTime = t
		}

		// 处理路径 (因为如果你用了聚合功能，p 可能是 "/config.json, /.env")
		// 我们把它按逗号切开，逐个处理，确保统计准确
		splitPaths := strings.Split(p, ",")
		for _, sp := range splitPaths {
			cleanPath := strings.TrimSpace(sp)
			if cleanPath == "" {
				continue
			}

			// 去重：如果这个路径之前没见过，就加入列表
			if !uniqueMap[cleanPath] {
				uniqueMap[cleanPath] = true
				paths = append(paths, cleanPath)
			}
		}
		count++ // 记录有多少条数据库记录(或是攻击波次)
	}

	// 4. 如果没有记录
	if len(paths) == 0 {
		return false, ""
	}

	// 5. 格式化输出
	summary := fmt.Sprintf("[%s]", strings.Join(paths, ", "))

	return true, summary
}

// loadNginxRTTServer 从环境变量或 config.json 读取 nginx RTT 服务器地址
func loadNginxRTTServer() string {
	// 1. 优先读环境变量
	if env := os.Getenv("NGINX_RTT_SERVER"); env != "" {
		log.Printf("[Config] RTT server from env: %s", env)
		return env
	}

	// 2. 其次读 config.json
	data, err := os.ReadFile("config.json")
	if err == nil {
		var cfg struct {
			NginxRTTServer string `json:"nginx_rtt_server"`
		}
		if err := json.Unmarshal(data, &cfg); err == nil && cfg.NginxRTTServer != "" {
			log.Printf("[Config] RTT server from config.json: %s", cfg.NginxRTTServer)
			return cfg.NginxRTTServer
		}
	}

	// 3. 兜底默认值
	log.Println("[Config] RTT server using default: http://192.168.253.1:9090")
	return "http://192.168.253.1:9090"
}
