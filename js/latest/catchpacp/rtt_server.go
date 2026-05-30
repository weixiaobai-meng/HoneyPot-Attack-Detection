package main

import (
	"fmt"
	"log"
	"net/http"
	"sync"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
)

var (
	rttMap      = make(map[string]float64)
	rttTime     = make(map[string]time.Time)
	rttMu       sync.RWMutex
	synAckTimes = make(map[string]time.Time)
	synAckMu    sync.Mutex
)

func main() {
	devices, err := pcap.FindAllDevs()
	if err != nil {
		log.Fatal(err)
	}

	for _, dev := range devices {
		if len(dev.Addresses) > 0 {
			go captureClientRTT(dev.Name, "tcp port 80 or tcp port 443")
		}
	}

	http.HandleFunc("/rtt", handleRTTQuery)
	http.HandleFunc("/debug", handleDebug) // 新增调试接口
	log.Println("RTT API 启动 :9090")
	log.Fatal(http.ListenAndServe(":9090", nil))
}

func captureClientRTT(device, filter string) {
	handle, err := pcap.OpenLive(device, 1600, true, pcap.BlockForever)
	if err != nil {
		log.Printf("[抓包][%s] 打开失败: %v", device, err)
		return
	}
	defer handle.Close()

	if err := handle.SetBPFFilter(filter); err != nil {
		log.Printf("[抓包][%s] BPF过滤设置失败: %v", device, err)
		return
	}

	log.Printf("[抓包][%s] 开始抓包，过滤: %s", device, filter)

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

				log.Printf("[匹配] 客户端 %s RTT=%.2fms", clientIP, rtt)
			} else {
				synAckMu.Unlock()
			}
		}
	}
}

func handleRTTQuery(w http.ResponseWriter, r *http.Request) {
	ip := r.URL.Query().Get("ip")
	if ip == "" {
		http.Error(w, "missing ip", 400)
		return
	}

	rttMu.RLock()
	rtt, ok := rttMap[ip]
	rttMu.RUnlock()

	if !ok {
		log.Printf("[API] 查询 %s -> 404", ip)
		http.NotFound(w, r)
		return
	}

	log.Printf("[API] 查询 %s -> %.2fms", ip, rtt)
	fmt.Fprintf(w, "%.2f", rtt)
}

// /debug 接口：查看当前内存中所有 RTT 数据
func handleDebug(w http.ResponseWriter, r *http.Request) {
	rttMu.RLock()
	defer rttMu.RUnlock()

	w.Header().Set("Content-Type", "text/plain")
	fmt.Fprintf(w, "当前 RTT 缓存条目数: %d\n\n", len(rttMap))
	for ip, rtt := range rttMap {
		age := time.Since(rttTime[ip]).Round(time.Second)
		fmt.Fprintf(w, "IP: %s  RTT: %.2fms  已缓存: %s\n", ip, rtt, age)
	}
}