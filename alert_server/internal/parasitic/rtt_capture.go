package parasitic

import (
	"fmt"
	"sync"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"github.com/sirupsen/logrus"
)

// RTT数据存储
var (
	rttMap      = make(map[string]float64)
	rttTime     = make(map[string]time.Time)
	rttMu       sync.RWMutex
	synAckTimes = make(map[string]time.Time)
	synAckMu    sync.Mutex
)

// GetTCPRTT 查询客户端的 TCP RTT（进程内直接读取，替代 HTTP 调用）
func GetTCPRTT(clientIP string) (float64, bool) {
	rttMu.RLock()
	rtt, ok := rttMap[clientIP]
	rttMu.RUnlock()
	return rtt, ok
}

// StartRTTCapture 启动 RTT 抓包捕获（在所有活跃网卡上）
// 应在后台 goroutine 中运行
func StartRTTCapture() {
	devices, err := pcap.FindAllDevs()
	if err != nil {
		logrus.Warnf("[RTT] 抓包初始化失败（可能需要管理员权限）: %v", err)
		return
	}

	started := 0
	for _, dev := range devices {
		if len(dev.Addresses) > 0 {
			go captureOnDevice(dev.Name, "tcp port 80 or tcp port 443")
			started++
		}
	}

	logrus.Infof("[RTT] 在 %d 个网卡上启动 TCP RTT 抓包", started)

	// 定期清理过期 RTT 记录（每 10 分钟清理超过 30 分钟的旧数据）
	go func() {
		ticker := time.NewTicker(10 * time.Minute)
		for range ticker.C {
			rttMu.Lock()
			now := time.Now()
			for ip, t := range rttTime {
				if now.Sub(t) > 30*time.Minute {
					delete(rttMap, ip)
					delete(rttTime, ip)
				}
			}
			rttMu.Unlock()
		}
	}()
}

func captureOnDevice(device, filter string) {
	handle, err := pcap.OpenLive(device, 1600, true, pcap.BlockForever)
	if err != nil {
		logrus.Debugf("[RTT][%s] 打开失败: %v", device, err)
		return
	}
	defer handle.Close()

	if err := handle.SetBPFFilter(filter); err != nil {
		logrus.Debugf("[RTT][%s] BPF过滤设置失败: %v", device, err)
		return
	}

	logrus.Debugf("[RTT][%s] 开始抓包，过滤: %s", device, filter)

	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())

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

		connID := fmt.Sprintf("%s:%d->%s:%d", ip.SrcIP, tcp.SrcPort, ip.DstIP, tcp.DstPort)

		if tcp.SYN && tcp.ACK {
			synAckMu.Lock()
			synAckTimes[connID] = packet.Metadata().Timestamp
			synAckMu.Unlock()

		} else if tcp.ACK && !tcp.SYN {
			revConnID := fmt.Sprintf("%s:%d->%s:%d", ip.DstIP, tcp.DstPort, ip.SrcIP, tcp.SrcPort)

			synAckMu.Lock()
			startTime, exists := synAckTimes[revConnID]
			if exists {
				rtt := float64(packet.Metadata().Timestamp.Sub(startTime).Milliseconds())
				clientIP := ip.SrcIP.String()

				rttMu.Lock()
				rttMap[clientIP] = rtt
				rttTime[clientIP] = time.Now()
				rttMu.Unlock()

				delete(synAckTimes, revConnID)
				synAckMu.Unlock()

				logrus.Debugf("[RTT] 客户端 %s RTT=%.2fms", clientIP, rtt)
			} else {
				synAckMu.Unlock()
			}
		}
	}
}

// RTTStats 返回 RTT 调试信息
func RTTStats() map[string]float64 {
	rttMu.RLock()
	defer rttMu.RUnlock()
	result := make(map[string]float64, len(rttMap))
	for ip, rtt := range rttMap {
		age := time.Since(rttTime[ip]).Round(time.Second)
		result[ip] = rtt
		_ = age // 可用于日志
	}
	return result
}
