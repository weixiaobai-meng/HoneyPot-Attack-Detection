package main

import (
	"encoding/json"
	"log"
	"sync"
	"time"
)

// 1. 定义暂存数据的容器
type SessionBuffer struct {
	Data          *parasitism // 指向 utils.go 中定义的数据结构
	CreatedAt     time.Time   // 创建时间(用于超时清理)
	IsHTTPReady   bool        // 标记：HTTP 指纹 (/info) 是否已收到
	IsWSReady     bool        // 标记：WS 延迟 (/ws) 是否已检测
	IsWebRTCReady bool        // 标记：WebRTC IP (/ips) 是否已收到
}

// 2. 全局管理器结构
type SessionManager struct {
	mu      sync.RWMutex              // 读写锁，保护并发安全
	buffers map[string]*SessionBuffer // 内存暂存区 Key=IP
	checkCh chan string               // 信号通道
}

// 初始化全局变量 sm
var sm = &SessionManager{
	buffers: make(map[string]*SessionBuffer),
	checkCh: make(chan string, 1000), // 缓冲 1000，防止高并发卡顿
}

// 3. 核心功能：获取或创建缓存 (并发安全)
func (s *SessionManager) GetBuffer(ip string) *SessionBuffer {
	s.mu.Lock()
	defer s.mu.Unlock()

	// 如果没有，就创建一个新的
	if _, ok := s.buffers[ip]; !ok {
		s.buffers[ip] = &SessionBuffer{
			Data: &parasitism{
				RemoteIP: ip,
				Ips:      []string{}, // 初始化为空切片，防止后续 append 出错
			},
			CreatedAt: time.Now(),
		}
	}
	return s.buffers[ip]
}

// 4. 后台监测协程 (需要在 main 中启动)
func (s *SessionManager) StartMonitor() {
	// 子协程 A: 负责接收信号并入库
	go func() {
		log.Println("🚀 [Monitor] 数据监测协程已启动...")
		for ip := range s.checkCh {
			s.checkAndSave(ip)
		}
	}()

	// 子协程 B: 负责清理死数据 (每分钟检查一次)
	go func() {
		ticker := time.NewTicker(1 * time.Minute)
		for range ticker.C {
			s.cleanUp()
		}
	}()
}

// 5. 检查并保存逻辑 (数据库操作在这里！)
func (s *SessionManager) checkAndSave(ip string) {
	s.mu.Lock()
	defer s.mu.Unlock()

	buf, exists := s.buffers[ip]
	if !exists {
		return
	}

	// 检查三个信号是否都已就绪
	if buf.IsHTTPReady && buf.IsWSReady && buf.IsWebRTCReady {
		log.Printf("✅ [Monitor] IP %s 数据完整，正在执行入库...", ip)

		// ============================================================
		// 🟢 关联蜜罐历史 (注入到 FingerprintDetails)
		// ============================================================
		hasHistory, historyInfo := CheckScanHistory(ip)

		if hasHistory {
			log.Printf("🔗 [SessionManager] 关联成功！IP %s 曾触发蜜罐: %s", ip, historyInfo)

			// 🎯 目标字段: buf.Data.FingerprintDetails
			if buf.Data.FingerprintDetails != "" {
				// 1. 定义 Map
				var jsonMap map[string]interface{}

				// 2. 解析 (Unmarshal)
				// 忽略错误处理，如果解析失败可能是空字符串，就不注入了
				if err := json.Unmarshal([]byte(buf.Data.FingerprintDetails), &jsonMap); err == nil {

					// 3. 注入数据！
					jsonMap["honeypot_history"] = historyInfo
					// jsonMap["risk_tag"] = "MALICIOUS" // 如果你想加标签

					// 4. 重新打包 (Marshal)
					if newBytes, err := json.Marshal(jsonMap); err == nil {
						// 5. 覆盖回原来的字段
						buf.Data.FingerprintDetails = string(newBytes)
						log.Println("💉 [注入] 已将蜜罐记录注入到 FingerprintDetails")
					}
				}
			}
		}
		// ============================================================

		// 这里调用 saveToDB 时，传入的 buf.Data.FingerprintDetails 已经是注入过的了
		saveToDB(buf.Data)

		// ============================================================
		// 🟢 Kafka 推送 (取消下面注释以启用)
		// ============================================================
		// go sendKafkaMessage(*buf.Data)

		// 清理内存
		delete(s.buffers, ip)
	}
}

// 6. 清理超时数据 (防止内存泄漏)
func (s *SessionManager) cleanUp() {
	s.mu.Lock()
	defer s.mu.Unlock()

	now := time.Now()
	for ip, buf := range s.buffers {
		// 如果超过 5 分钟还没凑齐，就删掉
		if now.Sub(buf.CreatedAt) > 5*time.Minute {
			// 可选：超时也强制入库（不完整数据），或者直接丢弃
			// saveToDB(buf.Data)
			delete(s.buffers, ip)
		}
	}
}

// 辅助函数：执行具体的 SQL 插入
// func saveToDB(data *parasitism) {
// 	if data.SessionToken == "" {
// 		log.Printf("⚠️ [DB Warning] IP %s 缺少 SessionToken", data.RemoteIP)
// 	}

// 	// 序列化 WebRTC IP 数组
// 	webrtcIPsJSON, _ := json.Marshal(data.Ips)
// 	if len(data.Ips) == 0 {
// 		webrtcIPsJSON = []byte("[]")
// 	}

// 	// ⚠️ 使用全局 db 变量
// 	stmt, err := db.Prepare(`
// 		INSERT INTO device_fingerprints (
// 			session_token, remote_ip, webrtc_ips, is_proxy, raw_json, timestamp
// 		) VALUES (?, ?, ?, ?, ?, ?)
// 	`)

// 	if err == nil {
// 		defer stmt.Close()
// 		_, execErr := stmt.Exec(
// 			data.SessionToken,
// 			data.RemoteIP,
// 			string(webrtcIPsJSON), // 存入 JSON 字符串
// 			data.ProxyDetectResult,
// 			data.FingerprintDetails, // 完整指纹 JSON
// 			time.Now().Format(time.RFC3339),
// 		)
// 		if execErr != nil {
// 			log.Printf("❌ [DB Insert Error] %v", execErr)
// 		} else {
// 			log.Printf("💾 [DB Success] 已存入 Session: %s", data.SessionToken)
// 		}
// 	} else {
// 		log.Printf("❌ [DB Prepare Error] %v", err)
// 	}
// }

func saveToDB(data *parasitism) {
	if data.SessionToken == "" {
		log.Printf("⚠️ [DB Warning] IP %s 缺少 SessionToken", data.RemoteIP)
	}

	// ✅ 1. 计算 GroupID (调用 utils.go 的算法)
	groupID := GetOrCreateGroupID(data.FingerprintDetails)

	// 2. 序列化 IPs
	webrtcIPsJSON, _ := json.Marshal(data.Ips)
	if len(data.Ips) == 0 {
		webrtcIPsJSON = []byte("[]")
	}

	// ✅ 3. 插入 (带 group_id)
	stmt, err := db.Prepare(`
		INSERT INTO device_fingerprints (
			group_id, session_token, remote_ip, webrtc_ips, is_proxy, raw_json, timestamp
		) VALUES (?, ?, ?, ?, ?, ?, ?)
	`)

	if err == nil {
		defer stmt.Close()
		_, execErr := stmt.Exec(
			groupID,
			data.SessionToken,
			data.RemoteIP,
			string(webrtcIPsJSON),
			data.ProxyDetectResult,
			data.FingerprintDetails,
			time.Now().Format(time.RFC3339),
		)
		if execErr != nil {
			log.Printf("❌ [DB Insert Error] %v", execErr)
		} else {
			log.Printf("💾 [DB Success] 已存入 (GroupID: %d)", groupID)
		}
	} else {
		log.Printf("❌ [DB Prepare Error] %v", err)
	}
}

// ============================================================
// 🟢 Kafka 推送函数 (取消下面所有注释以启用)
// ============================================================
/*
func sendKafkaMessage(data parasitism) {
	brokers := []string{"192.168.3.105:9092"} // Kafka broker地址
	topic := "fingerprint"

	// 配置生产者
	config := sarama.NewConfig()
	config.Producer.RequiredAcks = sarama.WaitForAll // 等待所有副本 ack
	config.Producer.Retry.Max = 5                    // 重试次数
	config.Producer.Return.Successes = true          // 成功反馈

	// 创建同步生产者
	producer, err := sarama.NewSyncProducer(brokers, config)
	if err != nil {
		log.Fatalf("创建Kafka生产者失败:%v", err)
	}
	defer producer.Close()

	// 直接构造目标格式的 map（只包含需要的字段）
	msgData := map[string]interface{}{
		"Time":                     data.Time,
		"RemoteIP":                 data.RemoteIP,
		"ProxyDetectResult":        data.ProxyDetectResult,
		"ProxyDetectResultDetails": data.ProxyDetectResultDetails,
		"IPs":                      data.Ips,
		"Path":                     data.Path,
		"Fingerprint":              data.Fingerprint,
		"FingerprintDetails":       data.FingerprintDetails,
	}

	// 将数据转换为 JSON 字符串
	dataBytes, err := json.Marshal(msgData)
	if err != nil {
		log.Fatalf("将数据转换为 JSON 失败: %v", err)
		return
	}

	// 构造消息
	msg := &sarama.ProducerMessage{
		Topic: topic,
		Value: sarama.StringEncoder(string(dataBytes)),
	}

	// 发送消息
	partition, offset, err := producer.SendMessage(msg)
	if err != nil {
		log.Fatalf("发送Kafka消息失败:%v", err)
	}

	log.Printf("Kafka消息发送成功, partition:%d,offset:%d\n", partition, offset)
}
*/
