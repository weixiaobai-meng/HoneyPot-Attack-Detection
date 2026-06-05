package main

import (
	"log"
	"net/http"
	"time"
)

func main() {
	setupLogger()

	InitDB()
	LoadFingerprintCache()
	
	log.Println("Parasitic_honey_backend_system start on 8080")

	// 初始化缓存清理
	go func() {
		for {
			time.Sleep(30 * time.Minute)
			now := time.Now()
			
			// 清理IP基础日志
			ipBaseLogs.Lock()
			for ip, entry := range ipBaseLogs.data {
				if entry == nil {
					delete(ipBaseLogs.data, ip)
					continue
				}
				
				timestamp, err := time.Parse(time.RFC3339Nano, entry.Timestamp)
				if err != nil {
					log.Printf("Invalid timestamp for IP %s: %v", ip, err)
					delete(ipBaseLogs.data, ip)
					continue
				}
				
				if now.Sub(timestamp) > 1*time.Hour {
					delete(ipBaseLogs.data, ip)
				}
			}
			ipBaseLogs.Unlock()
			
			// 清理最近IP记录
			recentIPs.Lock()
			for ip, lastSeen := range recentIPs.data {
				if now.Sub(lastSeen) > 1*time.Hour {
					delete(recentIPs.data, ip)
				}
			}
			recentIPs.Unlock()
		}
	}()

	var err error
	//初始连接延迟以及寄生信息
	connLatencyMap = make(map[string]*latency, 100)

	// ❌ 停掉本地抓包，RTT 改从 nginx 服务器查询
	// （反向代理架构下，bot 服务器抓不到客户端真实 IP 的 TCP 包）
	// devices, err := getAllInterfaces()
	// if err != nil {
	// 	log.Fatal("找不到可用的网卡:", err)
	// }
	// for _, device := range devices {
	// 	go listenTCPHandshake(device, "tcp port 80 or tcp port 8080")
	// }

	sm.StartMonitor()
	go reloadLogCache()

	// 初始化Bot检测器
	
	detector, err = NewBotDetector("bots.json")
	if err != nil {
		log.Printf("Warning: Failed to load bots.json, using default rules: %v", err)
		detector = createDefaultDetector()
	}

	
	http.HandleFunc("/bot-check", requestTypeMiddleware(botCheckHandler))
	http.HandleFunc("/ws", handleWebSocket)
	http.HandleFunc("/ips", handleIPS)
	http.HandleFunc("/info", handlePost)
	http.HandleFunc("/api/logs", logHandler)
	http.HandleFunc("/internal/target-ips", getTargetIPsHandler)
	http.HandleFunc("/api/pixel", handlePixel)
	http.HandleFunc("/api/ssh-log", handleSSHLog)
	http.HandleFunc("/api/ssh-list", handleGetSSHLogs)


	fs := http.FileServer(http.Dir("./static"))
	http.Handle("/static/", http.StripPrefix("/static/", fs))
	http.Handle("/display/", http.StripPrefix("/display/", fs))

	http.HandleFunc("/", requestTypeMiddleware(botDetectionMiddleware(mainHandler)))

	log.Fatal(http.ListenAndServe(":8080", nil))
}