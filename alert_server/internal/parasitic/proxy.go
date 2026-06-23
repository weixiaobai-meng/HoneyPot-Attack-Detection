package parasitic

import (
	"strings"

	"github.com/sirupsen/logrus"
)

// ProxyDetector 代理检测器
type ProxyDetector struct{}

// NewProxyDetector 创建代理检测器
func NewProxyDetector() *ProxyDetector {
	return &ProxyDetector{}
}

// DetectByIP 通过WebRTC IP匹配检测代理
// clientIP: 服务端看到的客户端IP
// webrtcIPs: 客户端通过WebRTC上报的IP列表
// 如果clientIP不在webrtcIPs中，说明使用了代理
func (pd *ProxyDetector) DetectByIP(clientIP string, webrtcIPs []string) bool {
	if len(webrtcIPs) == 0 {
		return false // 没有WebRTC数据，无法判定
	}

	for _, ip := range webrtcIPs {
		if strings.TrimSpace(ip) == clientIP {
			return false // 发现匹配，不是代理
		}
	}
	return true // IP不匹配，是代理
}

// DetectByRTT 通过RTT差异检测代理
// wsRTT: WebSocket测量的RTT(ms)
// tcpRTT: TCP握手测量的RTT(ms)
// 差值 >= 60ms 判定为代理
func (pd *ProxyDetector) DetectByRTT(wsRTT, tcpRTT float64) bool {
	if wsRTT <= 0 || tcpRTT <= 0 {
		return false
	}
	diff := wsRTT - tcpRTT
	if diff < 0 {
		diff = -diff
	}
	return diff >= 60
}

// QueryTCPRTT 从进程内RTT缓存查询TCP RTT（不再需要HTTP调用）
func (pd *ProxyDetector) QueryTCPRTT(clientIP string) (float64, error) {
	rtt, ok := GetTCPRTT(clientIP)
	if !ok {
		return 0, nil // 没有RTT数据，返回0而不是报错
	}
	logrus.Debugf("[Parasitic] 查询到客户端 %s 的TCP RTT: %.2fms", clientIP, rtt)
	return rtt, nil
}
