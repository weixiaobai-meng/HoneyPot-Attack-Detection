package main

import (
	"context"
	"net/http"
	"strings"
	"time"
)

func requestTypeMiddleware(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// 从Header中获取请求类型
		requestType := r.Header.Get("X-Request-Type")

		// 为没有标记的请求设置默认类型
		if requestType == "" {
			if strings.HasPrefix(r.URL.Path, "/bot-check") {
				requestType = "api"
			} else {
				requestType = "original"
			}
		}

		// 将请求类型存入上下文
		ctx := context.WithValue(r.Context(), "requestType", requestType)
		next(w, r.WithContext(ctx))
	}
}

func botDetectionMiddleware(next http.HandlerFunc) http.HandlerFunc {
    return func(w http.ResponseWriter, r *http.Request) {
        start := time.Now()
        ip := getClientIP(r)
        ua := r.UserAgent()

        // 构建基础日志
        baseLog := &BaseLog{
            Timestamp:  time.Now().Format(time.RFC3339Nano),
            IP:         ip,
            UserAgent:  ua,
            RequestURL: r.URL.Path,
            Method:     r.Method,
            IsBot:      detector.IsBot(ua),
            Duration:   time.Since(start).String(),
        }

        // 存入待处理队列
        pendingLogs.Lock()
        pendingLogs.data[ip] = baseLog
        pendingLogs.Unlock()

        // 启动延迟打印goroutine
        go func(ip string, base *BaseLog) {
            // 等待指定延迟时间
            time.Sleep(logDelayDuration)

            pendingLogs.Lock()
            defer pendingLogs.Unlock()

            // 检查日志是否仍在队列中（未被/bot-check消费）
            if _, exists := pendingLogs.data[ip]; exists {
                logUnified(UnifiedLog{
                    Base:       base,
                    Detection:  nil,
                    Standalone: true, // 标记为独立基础日志
                })
                delete(pendingLogs.data, ip)
            }
        }(ip, baseLog)

        next(w, r)
    }
}