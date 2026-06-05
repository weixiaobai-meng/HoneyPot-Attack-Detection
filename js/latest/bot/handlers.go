package main

import (
	"encoding/json"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/gorilla/websocket"
)

func loadFrontPage() ([]byte, error) {
	candidates := []string{}
	if env := strings.TrimSpace(os.Getenv("BOT_FRONT_HTML")); env != "" {
		candidates = append(candidates, env)
	}
	candidates = append(candidates,
		filepath.Join("static", "index.html"),
		"/var/www/front/index.html",
	)
	for _, candidate := range candidates {
		htmlBytes, err := os.ReadFile(candidate)
		if err == nil {
			return htmlBytes, nil
		}
	}
	return nil, fmt.Errorf("front page not found in %v", candidates)
}

func mainHandler(w http.ResponseWriter, r *http.Request) {
	// === 1. 瀹氫箟闄烽槺鍒楄〃 (Map缁撴瀯) ===
	// Key(宸﹁竟) = 闄烽槺璺緞
	// Value(鍙宠竟) = 瀵瑰簲鐨勪吉閫犺繑鍥炲唴瀹?
	traps := map[string]string{
		"/config.json": `{"db_host": "10.0.0.5", "secret": "sk-fake-token"}`,
		"/.env":        `DB_PASSWORD=root_pass_123\nAWS_KEY=AKIAIOSFODNN7EXAMPLE`,
		"/backup.sql":  `-- MySQL dump 10.13\n-- Host: localhost\nINSERT INTO users VALUES (1, 'admin', 'md5_hash');`,
		"/web.rar":     "Error: File is corrupted", // 鍋囪鏂囦欢鎹熷潖锛岄獥浠栦笅杞?
		"/admin/":      "<h1>403 Forbidden</h1>",   // 鍋囪鏈夊悗鍙颁絾娌℃潈闄?
	}

	// === 2. 妫€鏌ュ綋鍓嶈姹傛槸鍚﹁俯涓櫡闃?===
	// traps[r.URL.Path] 浼氬皾璇曞湪 map 閲屾壘褰撳墠璺緞
	// 濡傛灉鎵惧埌浜嗭紝ok 涓?true锛宖akeContent 灏辨槸涓婇潰鐨勪吉閫犲唴瀹?
	if fakeContent, ok := traps[r.URL.Path]; ok {
		ip := getClientIP(r)

		// 馃毃 璁板綍鏀诲嚮 (璋冪敤鐙珛鐨勮褰曞嚱鏁?
		go RecordHoneypotHit(ip, r.URL.Path, r.UserAgent())

		// 鏍规嵁鏂囦欢绫诲瀷璁剧疆涓€涓?Header锛屾紨寰楀儚涓€鐐?
		if strings.HasSuffix(r.URL.Path, ".json") {
			w.Header().Set("Content-Type", "application/json")
		} else {
			w.Header().Set("Content-Type", "text/plain")
		}

		// 杩斿洖浼€犳暟鎹?
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(fakeContent))
		return // 缁撴潫鎴樻枟锛屼笉瑕佽繑鍥炵湡鐨勭綉椤?
	}

	// === 3. 姝ｅ父鐢ㄦ埛鐨勯€昏緫 (鍙湁娌¤俯涓櫡闃辨墠浼氳蛋鍒拌繖閲? ===
	// 浣犵殑缃戦〉鍏ュ彛閫氬父鏄?"/" 鎴栬€?"/index.html"
	if r.URL.Path == "/" || r.URL.Path == "/index.html" {
		htmlBytes, err := loadFrontPage()
		if err != nil {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Write(htmlBytes)
		return
	}

	// === 4. 澶勭悊闈欐€佽祫婧愭垨鍏朵粬涓嶅瓨鍦ㄧ殑璺緞 ===
	// 濡傛灉鏃笉鏄櫡闃憋紝涔熶笉鏄椤碉紝鍙兘鏄?css/js 鎴栬€呯湡鐨勪笉瀛樺湪
	// 杩欓噷绠€鍗曞鐞嗕负 404锛屾垨鑰呬綘鍙互浜ょ粰 http.FileServer 澶勭悊闈欐€佹枃浠?
	http.NotFound(w, r)
}

func botCheckHandler(w http.ResponseWriter, r *http.Request) {
	//startTime := time.Now()
	enableCors(&w, r)
	if r.Method == http.MethodOptions {
		w.WriteHeader(http.StatusOK)
		return
	}
	if r.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed)
		json.NewEncoder(w).Encode(map[string]string{
			"error": "Method not allowed",
		})
		return
	}

	var data BotCheckRequest
	if err := json.NewDecoder(r.Body).Decode(&data); err != nil {
		log.Printf("[閿欒] 鏃犳晥鐨凧SON璇锋眰: %v", err)
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]string{
			"error": "Invalid JSON: " + err.Error(),
		})
		return
	}

	ip := getClientIP(r)

	// 寤虹珛 IP 鈫?Session 鍏崇郴
	recentIPs.RLock()
	_, seen := recentIPs.data[ip]
	recentIPs.RUnlock()

	if seen {
		ipToSession.Lock()
		ipToSession.data[ip] = data.SessionToken
		ipToSession.Unlock()
	}

	// 鑾峰彇鍩虹鏃ュ織
	var baseLog *BaseLog
	pendingLogs.Lock()
	// log.Printf("[璋冭瘯] === 寮€濮嬫煡鎵惧熀纭€鏃ュ織 ===")
	// log.Printf("[璋冭瘯] 鏌ユ壘IP: %s", ip)
	// log.Printf("[璋冭瘯] pendingLogs鏄犲皠澶у皬: %d", len(pendingLogs.data))

	if log, exists := pendingLogs.data[ip]; exists {
		baseLog = log
		delete(pendingLogs.data, ip) // 绉诲嚭闃熷垪
	}
	pendingLogs.Unlock()
	// log.Printf("[璋冭瘯] 鎵惧埌鍩虹鏃ュ織: %+v", baseLog)

	// 鑾峰彇鎴栧垱寤?session
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

	// 鏀堕泦鍒ゆ柇渚濇嵁
	var reasons []string
	if detector.IsBot(data.UserAgent) {
		reasons = append(reasons, "UA鍖归厤Bot瑙勫垯")
	}
	if len(mouseTrackWithT) < 5 {
		reasons = append(reasons, "Mouse trace points are too few")
	} else if isRegularMouseTrack(mouseTrackWithT) {
		reasons = append(reasons, "榧犳爣杞ㄨ抗杩囦簬瑙勫緥")
	}
	if len(data.ClickIntervals) > 1 {
		if variance := calculateClickVariance(data.ClickIntervals); variance < 1000 {
			reasons = append(reasons, fmt.Sprintf("鐐瑰嚮闂撮殧杩囦簬瑙勫緥(鏂瑰樊=%.2f)", variance))
		}
	} else if len(data.ClickIntervals) == 0 {
		reasons = append(reasons, "No click events recorded")
	}
	if len(s.Requests) > 2 {
		if freqScore := analyzeRequestFrequency(s.Requests); freqScore > 0 {
			reasons = append(reasons, fmt.Sprintf("璇锋眰棰戠巼寮傚父(寰楀垎+%d)", freqScore))
		}
	}
	if strings.Contains(strings.ToLower(data.UserAgent), "headlesschrome") {
		reasons = append(reasons, "HeadlessChrome UA")
	}

	// 鏋勫缓妫€娴嬫棩蹇?
	detectionLog := &DetectionLog{
		Timestamp:    time.Now().Format(time.RFC3339Nano),
		SessionID:    data.SessionToken,
		IP:           ip,
		Score:        score,
		MousePoints:  len(mouseTrackWithT),
		ClickCount:   len(data.ClickIntervals),
		Reasons:      reasons,
		IsBot:        score >= BotScoreThreshold,
		RequestURL:   r.URL.Path,
		Method:       r.Method,
		DetectMethod: "advanced", // 浣跨敤姝ｇ‘鐨勫瓧娈靛悕
	}

	// 杈撳嚭鍚堝苟鏃ュ織
	logUnified(UnifiedLog{
		Base:      baseLog,
		Detection: detectionLog,
		Abnormal:  baseLog == nil, // 鏍囪鏄惁缂哄皯鍩虹鏃ュ織
	})

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"isBot":       isBot,
		"score":       score,
		"mousePoints": len(mouseTrackWithT),
		"clickCount":  len(data.ClickIntervals),
	})
}

// 鏂板鐨刉ebSocket澶勭悊鍣?
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

// 鏂板鐨処PS澶勭悊鍣?
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

//		log.Printf("[webRTC] %v", logLine)
//		w.WriteHeader(http.StatusOK)
//		w.Write([]byte("IP addresses logged successfully"))
//	}
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

	// 鏈湴鏂囦欢鏃ュ織 (淇濈暀浣犲師鏉ョ殑閫昏緫)
	logLine := fmt.Sprintf("Time: %v, RemoteIP: %s, IPs: %v\n", time.Now().Format(time.RFC3339), ipAddress, requestBody.IPs)
	appendToFile("log/wrt_ips.log", logLine)
	log.Printf("[WebRTC] %v", logLine)

	// ==========================================
	// 馃洜锔?淇敼閮ㄥ垎锛氫娇鐢?SessionManager
	// ==========================================

	// 1. 鑾峰彇 Buffer
	buf := sm.GetBuffer(ipAddress)

	// 2. 鏇存柊 WebRTC 鏁版嵁 (鍔犻攣)
	sm.mu.Lock()
	buf.Data.Ips = requestBody.IPs // 瀛樺叆 IP 鏁扮粍
	buf.IsWebRTCReady = true       // 馃毄 鏍囪 WebRTC 灏辩华
	sm.mu.Unlock()

	// 3. 鍙戦€佷俊鍙?
	select {
	case sm.checkCh <- ipAddress:
	default:
	}

	w.WriteHeader(http.StatusOK)
	w.Write([]byte("IP addresses logged successfully"))
}

// 鏂板鐨凱OST澶勭悊鍣?
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

	// 鏈湴鏂囦欢鏃ュ織 (淇濈暀)
	logLine := fmt.Sprintf(
		"Time: %s, RemoteIP: %s, Path: %v, Fingerprint: %v, Details: %v\n",
		currentTime, ipAddress, realPath, fingerprintID, string(details),
	)
	appendToFile("log/fingerprint.log", logLine)

	log.Printf("[Fingerprint] RemoteIP: %s, Path: %v, Fingerprint: %v", ipAddress, realPath, fingerprintID)

	// ==========================================
	// 馃洜锔?淇敼閮ㄥ垎锛氫娇鐢?SessionManager
	// ==========================================

	// 1. 鑾峰彇 Buffer
	buf := sm.GetBuffer(ipAddress)

	// 2. 鏇存柊 HTTP 鏁版嵁 (鍔犻攣)
	sm.mu.Lock()
	buf.Data.SessionToken = sessionToken
	buf.Data.FingerprintDetails = string(details)
	buf.Data.Path = realPath
	buf.Data.Fingerprint = fingerprintID

	buf.IsHTTPReady = true // 馃毄 鏍囪 HTTP 灏辩华
	sm.mu.Unlock()

	// 3. 鍙戦€佷俊鍙?
	select {
	case sm.checkCh <- ipAddress:
	default:
	}

	w.WriteHeader(http.StatusOK)
}

// 杈呭姪缁撴瀯浣擄細浠呯敤浜庤В鏋?FingerprintData 涓殑鍏抽敭瀛楁
type FingerprintMeta struct {
	Path     string `json:"path"`
	PathAlt  string `json:"Path"` // 鍏煎澶у皬鍐?
	OS       string `json:"os"`
	TimeZone string `json:"timeZone"`
	Language string `json:"language"`
}

// 鏍稿績鏃ュ織鏌ヨ鎺ュ彛 (鏀寔绛涢€?+ 缁煎悎浠ｇ悊鍒ゅ畾閫昏緫)
func logHandler(w http.ResponseWriter, r *http.Request) {
	enableCors(&w, r)
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// === 1. 瑙ｆ瀽鍙傛暟 ===
	q := r.URL.Query()

	page, _ := strconv.Atoi(q.Get("page"))
	size, _ := strconv.Atoi(q.Get("size"))
	if page < 1 {
		page = 1
	}
	if size < 1 || size > 100 {
		size = 10
	}

	// 绛涢€夊弬鏁版彁鍙栧櫒
	parseParam := func(key string) []string {
		val := q.Get(key)
		if val == "" {
			return nil
		}
		return strings.Split(val, ",")
	}

	filterTargets := parseParam("target")
	filterBots := parseParam("is_bot")
	filterProxies := parseParam("is_proxy") // 鍓嶇浼?"true" 鎴?"false"
	filterOS := parseParam("os")
	filterTZ := parseParam("timezone")
	filterLangs := parseParam("language")

	cacheMutex.RLock()
	defer cacheMutex.RUnlock()

	filteredLogs := make([]LogRecord, 0)

	// Options Sets
	optTargets := make(map[string]bool)
	optOS := make(map[string]bool)
	optTZ := make(map[string]bool)
	optLang := make(map[string]bool)

	// 閫氱敤鍖归厤鍑芥暟
	matchExact := func(filters []string, val string) bool {
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

	// === 2. 閬嶅巻鍏ㄩ噺鏃ュ織 ===
	for _, rawLog := range logCache {
		// 澶嶅埗涓€浠?log 鏁版嵁锛岄伩鍏嶄慨鏀瑰師濮嬬紦瀛?(鍥犱负鎴戜滑瑕佷慨鏀?ProxyDetectResult 鐢ㄤ簬灞曠ず)
		log := rawLog

		// --- A. 瑙ｆ瀽鎸囩汗鍏冩暟鎹?---
		var fp FingerprintMeta
		if log.FingerprintData != "" {
			_ = json.Unmarshal([]byte(log.FingerprintData), &fp)
		}

		// 褰掍竴鍖?Target
		currentPath := fp.Path
		if currentPath == "" {
			currentPath = fp.PathAlt
		}
		if currentPath == "" {
			currentPath = "Unknown"
		}

		// --- B. 鏀堕泦閫夐」 ---
		if currentPath != "Unknown" {
			optTargets[currentPath] = true
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

		// --- C. 鏍稿績淇敼锛氱患鍚堜唬鐞嗗垽瀹氶€昏緫 ---
		// 閫昏緫锛欼P涓嶄竴鑷?? True : LatencyResult

		isProxy := false

		// 1. 妫€鏌?IP 鏄惁涓嶄竴鑷?(WebRTC IP vs Remote IP)
		// 鍙湁褰撹幏鍙栧埌浜?WebRTC IPs 鏃舵墠姣旇緝
		if len(log.IPs) > 0 {
			matchFound := false
			for _, webRTCIP := range log.IPs {
				if webRTCIP == log.RemoteIP {
					matchFound = true
					break
				}
			}
			// 濡傛灉 RemoteIP 涓嶅湪 WebRTC IPs 鍒楄〃涓?-> 鍒ゅ畾涓轰唬鐞?
			if !matchFound {
				isProxy = true
			}
		}

		// 2. 濡傛灉 IP 涓€鑷?(鎴栨病鎷垮埌 WebRTC)锛屽垯鍥為€€浣跨敤寤惰繜妫€娴嬬粨鏋?
		if !isProxy {
			// log.ProxyDetectResult 鏄瓧绗︿覆 "true"/"false"
			if log.ProxyDetectResult == "true" {
				isProxy = true
			}
		}

		// 3. 灏嗚绠楀悗鐨勬渶缁堢粨鏋滆祴鍊煎洖鍘?(鐢ㄤ簬绛涢€?鍜?杩斿洖缁欏墠绔睍绀?
		finalProxyStatus := strconv.FormatBool(isProxy) // "true" or "false"
		log.ProxyDetectResult = finalProxyStatus

		// --- D. 鎵ц绛涢€夐€昏緫 ---

		// 1. 浠ｇ悊绛涢€?(浣跨敤鍒氭墠璁＄畻鍑虹殑 finalProxyStatus)
		if !matchExact(filterProxies, finalProxyStatus) {
			continue
		}

		// 2. Target 绛涢€?
		if !matchExact(filterTargets, currentPath) {
			continue
		}

		// 3. Bot 绛涢€?
		if !matchExact(filterBots, strconv.FormatBool(log.IsBot)) {
			continue
		}

		// 4. 鏃跺尯绛涢€?
		if !matchExact(filterTZ, fp.TimeZone) {
			continue
		}

		// 5. 璇█绛涢€?
		if !matchExact(filterLangs, fp.Language) {
			continue
		}

		// 6. 鎿嶄綔绯荤粺绛涢€?(妯＄硦鍖归厤)
		if len(filterOS) > 0 {
			osMatched := false
			for _, f := range filterOS {
				if strings.Contains(strings.ToLower(fp.OS), strings.ToLower(f)) {
					osMatched = true
					break
				}
			}
			if !osMatched {
				continue
			}
		}

		// --- E. 閫氳繃绛涢€夛紝鍔犲叆缁撴灉 ---
		filteredLogs = append(filteredLogs, log)
	}

	// === 3. 鍒嗛〉 ===
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

	// === 4. 鏍煎紡鍖栭€夐」 ===
	getKeys := func(m map[string]bool) []string {
		keys := make([]string, 0, len(m))
		for k := range m {
			if k != "" {
				keys = append(keys, k)
			}
		}
		return keys
	}

	// === 5. 杩斿洖 ===
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

// getTargetIPsHandler 涓撻棬鐢ㄤ簬缁?Python 涓棿浠舵彁渚涘師濮?IP 鏁版嵁
func getTargetIPsHandler(w http.ResponseWriter, r *http.Request) {
	// 1. 鍩虹妫€鏌?
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// 2. 鑾峰彇 target 鍙傛暟
	targetParam := r.URL.Query().Get("target")
	if targetParam == "" {
		http.Error(w, "Target parameter is required", http.StatusBadRequest)
		return
	}

	// 3. 鍔犺閿侊紝鍑嗗閬嶅巻
	cacheMutex.RLock()
	defer cacheMutex.RUnlock()

	// 浣跨敤 Map 杩涜 IP 鍘婚噸 (Set)
	uniqueIPs := make(map[string]bool)
	// 鏈€缁堣繑鍥炵殑鍒囩墖
	resultIPs := make([]string, 0)

	// 4. 閬嶅巻鍐呭瓨涓殑鍏ㄩ噺鏃ュ織
	for _, log := range logCache {

		// === A. 瑙ｆ瀽閫昏緫 (淇濇寔涓庡垪琛ㄩ〉涓€鑷? ===
		// 鎴戜滑闇€瑕佺‘瀹氳繖鏉℃棩蹇楀埌搴曞睘浜庡摢涓?Target
		currentTarget := "Unknown"

		// 浼樺厛浠?FingerprintData 瑙ｆ瀽 path/Path
		if log.FingerprintData != "" {
			var fpData map[string]interface{}
			// 娉ㄦ剰锛氳繖閲屽拷鐣ラ敊璇紝瑙ｆ瀽澶辫触灏卞綋娌¤В鏋愬埌
			if json.Unmarshal([]byte(log.FingerprintData), &fpData) == nil {
				if v, ok := fpData["path"].(string); ok {
					currentTarget = v
				} else if v, ok := fpData["Path"].(string); ok {
					currentTarget = v
				}
			}
		}

		// === B. 鍖归厤閫昏緫 ===
		if currentTarget == targetParam {
			ip := log.RemoteIP

			// 杩囨护鏃犳晥 IP 骞跺幓閲?
			if ip != "" && ip != "Unknown" && !uniqueIPs[ip] {
				uniqueIPs[ip] = true
				resultIPs = append(resultIPs, ip)
			}
		}
	}

	// 5. 杩斿洖 JSON 缁撴灉
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"target": targetParam,
		"count":  len(resultIPs), // 杩斿洖 IP 鎬绘暟鏂逛究璋冭瘯
		"ips":    resultIPs,      // 鏍稿績鏁版嵁锛欼P 瀛楃涓叉暟缁?
	})
}

// 1. 瀹氫箟 1x1 閫忔槑 GIF 鐨勪簩杩涘埗鏁版嵁
var pixelData = []byte{
	0x47, 0x49, 0x46, 0x38, 0x39, 0x61, 0x01, 0x00, 0x01, 0x00,
	0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0xff, 0xff, 0xff, 0x21,
	0xf9, 0x04, 0x01, 0x00, 0x00, 0x00, 0x00, 0x2c, 0x00, 0x00,
	0x00, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x02, 0x01, 0x44,
	0x00, 0x3b,
}

// 2. 鏂板澶勭悊 CSS 鍩嬬偣璇锋眰鐨?Handler
func handlePixel(w http.ResponseWriter, r *http.Request) {
	// 浣跨敤浣犵幇鏈夌殑宸ュ叿鍑芥暟鑾峰彇 IP
	ip := getClientIP(r)
	ua := r.UserAgent()
	referer := r.Referer()
	if referer == "" {
		referer = "direct/unknown"
	}

	currentTime := time.Now().Format(time.RFC3339)

	// 璁板綍鏃ュ織锛氫綘鍙互閫夋嫨澶嶇敤 logUnified 閫昏緫锛屾垨鑰呭儚 handleIPS 閭ｆ牱鐩存帴鍐欐枃浠?
	// 杩欓噷涓轰簡绠€鍗曠洿鎺ワ紝妯′豢 handleIPS 鍐欏叆鐙珛鏂囦欢
	logLine := fmt.Sprintf("Time: %s | Type: CSS_TRACK | IP: %s | UA: %s | Ref: %s\n",
		currentTime, ip, ua, referer)

	// 鍐欏叆涓撻棬鐨勬棩蹇楁枃浠讹紝鏂逛究鍖哄垎
	appendToFile("log/css_track.log", logLine)

	// 鍦ㄦ帶鍒跺彴鎵撳嵃锛屾柟渚胯皟璇?
	log.Printf("[CSS杩借釜] %s", logLine)

	// === 鍏抽敭鍝嶅簲璁剧疆 ===
	w.Header().Set("Content-Type", "image/gif")
	// 绂佹缂撳瓨锛岀‘淇濇瘡娆¤闂〉闈㈤兘瑙﹀彂璇锋眰
	w.Header().Set("Cache-Control", "no-cache, no-store, must-revalidate")
	w.Header().Set("Pragma", "no-cache")
	w.Header().Set("Expires", "0")

	// 杩斿洖 GIF 鍥剧墖鏁版嵁
	w.Write(pixelData)
}

// 1. 瀹氫箟鎺ユ敹缁撴瀯浣?(瀵瑰簲 SSH 铚滅綈鍙戦€佺殑 JSON)
type SSHLogRequest struct {
	Msg           string `json:"msg"`
	Level         string `json:"level"`
	User          string `json:"duser"`          // 瀵瑰簲鍙戦€佺鐨?duser
	Password      string `json:"password"`       // 瀵瑰簲鍙戦€佺鐨?password
	Src           string `json:"src"`            // 瀵瑰簲鍙戦€佺鐨?src (IP:Port)
	ClientVersion string `json:"client_version"` // 瀹㈡埛绔増鏈?
	Time          string `json:"time"`
}

// 2. 鎺ユ敹 SSH 鏃ュ織鐨?Handler
func handleSSHLog(w http.ResponseWriter, r *http.Request) {
	// 鍏佽璺ㄥ煙 (濡傛灉鏄湰鏈轰簰鍙戝叾瀹炰笉闇€瑕侊紝浣嗕负浜嗕繚闄?
	enableCors(&w, r)
	if r.Method == http.MethodOptions {
		w.WriteHeader(http.StatusOK)
		return
	}

	var logData SSHLogRequest
	if err := json.NewDecoder(r.Body).Decode(&logData); err != nil {
		http.Error(w, "JSON 瑙ｆ瀽澶辫触", http.StatusBadRequest)
		return
	}

	// 绠€鍗曠殑杩囨护锛氬彧璁板綍鍚湁瀵嗙爜鐨勫皾璇曪紝鎴栬€呬綘鍙互璁板綍鎵€鏈夎繛鎺?
	// 鍙戦€佺鐨?msg 閫氬父鏄?"Request with password"
	if logData.Password == "" && logData.Msg != "Request with password" {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("Ignored (No password)"))
		return
	}

	// 澶勭悊 IP (鍘绘帀绔彛鍙?
	ip := logData.Src
	if strings.Contains(ip, ":") {
		host, _, err := net.SplitHostPort(ip)
		if err == nil {
			ip = host
		}
	}

	if db == nil {
		log.Printf("[SSH] db disabled, skip persistent store for ip=%s user=%s", ip, logData.User)
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("Logged (db disabled)"))
		return
	}

	// 鍏ュ簱
	stmt, err := db.Prepare(`
		INSERT INTO ssh_attacks (ip, username, password, client_version, raw_log, timestamp)
		VALUES (?, ?, ?, ?, ?, ?)
	`)
	if err != nil {
		log.Printf("SSH 鍏ュ簱 Prepare 澶辫触: %v", err)
		http.Error(w, "DB Error", http.StatusInternalServerError)
		return
	}
	defer stmt.Close()

	// 瀛樺叆鏁版嵁搴?
	// raw_log 瀛樹竴涓嬪師濮?msg 澶囨煡
	timestamp := time.Now().Format(time.RFC3339)
	_, err = stmt.Exec(ip, logData.User, logData.Password, logData.ClientVersion, logData.Msg, timestamp)

	if err != nil {
		log.Printf("SSH 鏁版嵁鍐欏叆澶辫触: %v", err)
	} else {
		log.Printf("馃毃 [SSH铚滅綈] 鎹曡幏鏀诲嚮! IP:%s User:%s Pass:%s", ip, logData.User, logData.Password)
	}

	w.WriteHeader(http.StatusOK)
	w.Write([]byte("Logged"))
}

// 3. (鍙€? 鎻愪緵涓€涓帴鍙ｇ粰鍓嶇鏌ヨ SSH 鏀诲嚮鍒楄〃
func handleGetSSHLogs(w http.ResponseWriter, r *http.Request) {
	enableCors(&w, r)

	if db == nil {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte("[]"))
		return
	}

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
