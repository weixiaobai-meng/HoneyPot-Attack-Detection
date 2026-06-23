package parasitic

import (
	"encoding/json"
	"log"
	"server/internal/models"
	"sync"
	"time"

	"gorm.io/gorm"
)

// BufferData 会话缓冲区数据
type BufferData struct {
	SessionToken       string
	FingerprintDetails string
	Path               string
	Fingerprint        string
	Ips                []string
	Browser            string
	OS                 string
	UserAgent          string

	IsHTTPReady    bool
	IsWSReady      bool
	IsWebRTCReady  bool

	WSRTT    float64
	TCPRTT   float64
}

// BufferEntry 缓冲区条目
type BufferEntry struct {
	Data      *BufferData
	LastTouch time.Time
}

// httpFallbackTimeout 是 HTTP 指纹已就绪但 WebRTC 未到达时的降级保存等待时间。
// 超过此时间仍无 WebRTC 数据，则仅保存已有的 HTTP 指纹数据，不再无限等待。
const httpFallbackTimeout = 30 * time.Second

// SessionManager 会话管理器
// 协调三个异步通道的数据（HTTP指纹 / WebRTC IP / WebSocket延迟）
type SessionManager struct {
	mu          sync.RWMutex
	buffers     map[string]*BufferEntry // key: clientIP
	timeout     time.Duration
	db          *gorm.DB
	checkCh     chan string
	stopCh      chan struct{}
}

// NewSessionManager 创建Session管理器
func NewSessionManager(db *gorm.DB, timeoutSeconds int) *SessionManager {
	sm := &SessionManager{
		buffers: make(map[string]*BufferEntry),
		timeout: time.Duration(timeoutSeconds) * time.Second,
		db:      db,
		checkCh: make(chan string, 1000),
		stopCh:  make(chan struct{}),
	}
	return sm
}

// StartMonitor 启动监控goroutine
func (sm *SessionManager) StartMonitor() {
	go sm.cleanupLoop()
	go sm.checkLoop()
}

// Stop 停止监控
func (sm *SessionManager) Stop() {
	close(sm.stopCh)
}

// GetBuffer 获取或创建IP对应的缓冲区
func (sm *SessionManager) GetBuffer(ip string) *BufferData {
	sm.mu.Lock()
	defer sm.mu.Unlock()

	entry, exists := sm.buffers[ip]
	if !exists {
		entry = &BufferEntry{
			Data:      &BufferData{},
			LastTouch: time.Now(),
		}
		sm.buffers[ip] = entry
	}
	entry.LastTouch = time.Now()
	return entry.Data
}

// cleanupLoop 定期清理过期缓冲区
func (sm *SessionManager) cleanupLoop() {
	ticker := time.NewTicker(1 * time.Minute)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			sm.cleanup()
		case <-sm.stopCh:
			return
		}
	}
}

// cleanup 清理过期缓冲区
// - HTTP 已就绪但 WebRTC 超过 httpFallbackTimeout 未到达 → 降级保存已有数据
// - 完全无数据超过 sm.timeout → 直接丢弃
func (sm *SessionManager) cleanup() {
	sm.mu.Lock()
	defer sm.mu.Unlock()

	now := time.Now()
	for ip, entry := range sm.buffers {
		elapsed := now.Sub(entry.LastTouch)

		if entry.Data.IsHTTPReady && !entry.Data.IsWebRTCReady && elapsed > httpFallbackTimeout {
			// HTTP 指纹已就绪，但 WebRTC 在 30 秒内未到达 — 降级保存已有数据
			data := entry.Data
			delete(sm.buffers, ip)
			go func(savedIP string, savedData *BufferData) {
				sm.saveToDB(savedIP, savedData)
				log.Printf("[SessionManager] HTTP-only 降级保存 IP:%s (WebRTC 未到达，等待 %.0fs)", savedIP, elapsed.Seconds())
			}(ip, data)
		} else if elapsed > sm.timeout {
			// 超时且无有效数据，丢弃
			delete(sm.buffers, ip)
		}
	}
}

// checkLoop 检查并保存完整数据
func (sm *SessionManager) checkLoop() {
	for {
		select {
		case ip := <-sm.checkCh:
			sm.checkAndSave(ip)
		case <-sm.stopCh:
			return
		}
	}
}

// checkAndSave 检查数据是否完整，完整则入库
func (sm *SessionManager) checkAndSave(ip string) {
	sm.mu.Lock()
	entry, exists := sm.buffers[ip]
	if !exists {
		sm.mu.Unlock()
		return
	}
	data := entry.Data

	// 检查三个通道数据是否都就绪
	if !data.IsHTTPReady || !data.IsWebRTCReady {
		sm.mu.Unlock()
		return
	}

	// 数据已就绪，从缓冲区移除
	delete(sm.buffers, ip)
	sm.mu.Unlock()

	// 异步写入数据库
	go sm.saveToDB(ip, data)
}

// saveToDB 将数据持久化到数据库
func (sm *SessionManager) saveToDB(ip string, data *BufferData) {
	if sm.db == nil {
		return
	}

	// 构建WebRTC IPs JSON
	webrtcIPsJSON := "[]"
	if len(data.Ips) > 0 {
		if b, err := json.Marshal(data.Ips); err == nil {
			webrtcIPsJSON = string(b)
		}
	}

	// 构建代理检测结果
	isProxy := false
	if len(data.Ips) > 0 {
		matchFound := false
		for _, webrtcIP := range data.Ips {
			if webrtcIP == ip {
				matchFound = true
				break
			}
		}
		if !matchFound {
			isProxy = true
		}
	}
	proxyResult := "false"
	if isProxy {
		proxyResult = "true"
	}

	record := models.DeviceFingerprint{
		RemoteIP:        ip,
		SessionToken:    data.SessionToken,
		FingerprintData: data.FingerprintDetails,
		FingerprintID:   data.Fingerprint,
		TargetURL:       data.Path,
		Browser:         data.Browser,
		OS:              data.OS,
		UserAgent:       data.UserAgent,
		WebRTCIPs:       webrtcIPsJSON,
		IsProxy:         isProxy,
		ProxyDetectResult: proxyResult,
		Timestamp:       time.Now(),
	}

	if err := sm.db.Create(&record).Error; err != nil {
		log.Printf("[SessionManager] 保存设备指纹失败: %v", err)
	} else {
		log.Printf("[SessionManager] 设备指纹已保存 IP:%s", ip)
	}
}

// SignalReady 标记某个通道数据就绪并尝试合并
func (sm *SessionManager) SignalReady(ip string) {
	select {
	case sm.checkCh <- ip:
	default:
		// 通道满时跳过，下次清理会处理
	}
}
