package pkg

import (
	"net"
	"os"
	"sync"
	"time"

	"github.com/sirupsen/logrus"
	"golang.org/x/time/rate"
)

type visitor struct {
	Limiter  *rate.Limiter
	lastSeen time.Time
	Attempts int
}

type Filter struct {
	blocklist map[string]*net.IPNet // 黑名单
	whitelist map[string]*net.IPNet // 白名单
	visitors  map[string]*visitor   // 访问者
	mu        sync.Mutex
}

func NewFileter(whitelist map[string]*net.IPNet, blocklist map[string]*net.IPNet) *Filter {
	return &Filter{
		whitelist: whitelist,
		blocklist: blocklist,
		visitors:  make(map[string]*visitor),
		mu:        sync.Mutex{},
	}
}

// 获取黑名单
func (ft *Filter) GetBlockList() map[string]*net.IPNet {
	ft.mu.Lock()
	defer ft.mu.Unlock()
	return ft.blocklist
}

// 获取白名单
func (ft *Filter) GetWhiteList() map[string]*net.IPNet {
	ft.mu.Lock()
	defer ft.mu.Unlock()
	return ft.whitelist
}

// 互斥获取访问者信息
func (ft *Filter) GetVisitor(ip string) *visitor {
	ft.mu.Lock()
	defer ft.mu.Unlock()

	if IsInIPlist(ip, ft.blocklist) {
		return &visitor{Limiter: rate.NewLimiter(0, 0)} // 禁止任何请求
	}

	v, exists := ft.visitors[ip]
	if !exists {
		limiter := rate.NewLimiter(1, 5) // 每秒一个请求，最多5个请求的缓存
		ft.visitors[ip] = &visitor{limiter, time.Now(), 0}
		return ft.visitors[ip]
	}

	v.lastSeen = time.Now()
	return v
}

// 删除访问者信息缓存
func (ft *Filter) CleanupVisitors() {
	for {
		time.Sleep(time.Minute)
		ft.mu.Lock()
		for ip, v := range ft.visitors {
			if time.Since(v.lastSeen) > 3*time.Minute {
				delete(ft.visitors, ip)
			}
		}
		ft.mu.Unlock()
	}
}

// 将 IP 添加到黑名单，并写入 block.list 文件
func (ft *Filter) AddToBlockIP(ip string) bool {
	ft.mu.Lock() // 上锁
	defer ft.mu.Unlock()
	if IsInIPlist(ip, ft.blocklist) { // 判断IP是否已经拉黑，若未拉黑
		logrus.Info("[Blocklist] 添加IP黑名单,IP：", ip)
		// TODO:加入黑名单
		_, ipnet, err := net.ParseCIDR(ip)
		if err != nil {
			logrus.Error("[Config] 添加黑名单解析出错,", err)
			return false
		}
		ft.blocklist[ip] = ipnet
		file, err := os.OpenFile(Cfg.BlocklistFile, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
		if err != nil {
			logrus.Error("[Blocklist] 打开黑名单文件出错,", err)
			return false
		}
		defer file.Close()
		_, err = file.WriteString(ip + "\n")
		if err != nil {
			logrus.Error("[Blocklist] 写入黑名单文件出错,", err)
			return false
		}
	} else {
		logrus.Info("[Blocklist] IP黑名单已存在,IP：", ip)
	}
	return true
}
