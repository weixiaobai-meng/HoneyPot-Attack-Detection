package handlers

import (
	"net"
	"net/http"
	"os"
	"server/internal/models"
	"server/pkg"

	"github.com/gin-gonic/gin"
	"github.com/sirupsen/logrus"
)

// 查询所有过滤白名单
func FindFilterWhiteListHandler(c *gin.Context) {
	pkg.Cfg.Mu.Lock()
	defer pkg.Cfg.Mu.Unlock()

	var whiteList = make([]string, len(pkg.Cfg.Whitelist))
	idx := 0
	for ip := range pkg.Cfg.Whitelist {
		whiteList[idx] = ip
		idx++
	}
	c.JSON(http.StatusAccepted, gin.H{
		"code":    0,
		"message": "success",
		"data":    whiteList,
	})
}

// 添加白名单
func CreateFilterWhite(c *gin.Context) {
	pkg.Cfg.Mu.Lock()
	defer pkg.Cfg.Mu.Unlock()

	var req models.CreateWhiteRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		logrus.Errorf("参数错误, %v", err.Error())
		c.JSON(http.StatusOK, gin.H{
			"code":    1,
			"message": "参数错误",
		})
		return
	}
	ipToAdd := req.Ip

	// 解析IP
	_, ipnet, err := net.ParseCIDR(ipToAdd)
	if err != nil {
		// 如果解析失败，可能是单个IP地址，手动添加/32前缀作为单个IP处理
		var ip net.IP
		if ip = net.ParseIP(ipToAdd); ip == nil {
			// 不是单个IP
			logrus.Errorf("白名单IP添加出错: %v", err.Error())
			c.JSON(http.StatusOK, gin.H{
				"code":    1,
				"message": "白名单IP添加出错:" + err.Error(),
			})
			return
		}
		// 是单个IP
		ipnet = &net.IPNet{
			IP:   ip,
			Mask: net.CIDRMask(32, 32),
		}
	}

	// 判断IP是否已经存在
	if _, exist := pkg.Cfg.Whitelist[ipToAdd]; exist {
		logrus.Errorf("白名单IP已存在")
		c.JSON(http.StatusOK, gin.H{
			"code":    1,
			"message": "白名单IP已存在",
		})
		return
	}

	// 添加新IP
	pkg.Cfg.Whitelist[ipnet.String()] = ipnet

	// 写入到文件
	whiteListFile, err := os.OpenFile(pkg.Cfg.WhitelistFile, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		logrus.Errorf("白名单打开出错: %v", err.Error())
		c.JSON(http.StatusBadRequest, gin.H{
			"code":    1,
			"message": "白名单IP添加出错:" + err.Error(),
		})
		return
	}
	defer whiteListFile.Close()

	if _, err := whiteListFile.WriteString("\n" + ipToAdd); err != nil { // 写入ip_white.list
		logrus.Errorf("白名单写入出错: %v", err.Error())
		c.JSON(http.StatusBadRequest, gin.H{
			"code":    1,
			"message": "白名单IP添加出错:" + err.Error(),
		})
		return
	}

	logrus.Infof("白名单添加成功: %s", ipnet.String())
	c.JSON(http.StatusOK, gin.H{
		"code":    0,
		"message": "success:",
	})
}

// 删除白名单
func DeleteFilterWhite(c *gin.Context) {
	pkg.Cfg.Mu.Lock()
	defer pkg.Cfg.Mu.Unlock()

	var req models.CreateWhiteRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		logrus.Errorf("参数错误, %v", err.Error())
		c.JSON(http.StatusOK, gin.H{
			"code":    1,
			"message": "参数错误",
		})
		return
	}
	ipToAdd := req.Ip
	// 解析IP
	_, ipnet, err := net.ParseCIDR(ipToAdd)
	if err != nil {
		// 如果解析失败，可能是单个IP地址，手动添加/32前缀作为单个IP处理
		var ip net.IP
		if ip = net.ParseIP(ipToAdd); ip == nil {
			// 不是单个IP
			logrus.Errorf("白名单IP添加出错: %v", err.Error())
			c.JSON(http.StatusOK, gin.H{
				"code":    1,
				"message": "白名单IP添加出错:" + err.Error(),
			})
			return
		}
		// 是单个IP
		ipnet = &net.IPNet{
			IP:   ip,
			Mask: net.CIDRMask(32, 32),
		}
	}
	// 判断是否已经存在
	if _, exist := pkg.Cfg.Whitelist[ipnet.String()]; !exist {
		logrus.Errorf("白名单IP不存在")
		c.JSON(http.StatusOK, gin.H{
			"code":    1,
			"message": "白名单IP不存在",
		})
		return
	}

	// 从map中删除
	delete(pkg.Cfg.Whitelist, ipnet.String())

	// 覆盖IP白名单文件
	whiteListFile, err := os.OpenFile(pkg.Cfg.WhitelistFile, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0644)
	if err != nil {
		logrus.Errorf("白名单打开出错: %v", err.Error())
		c.JSON(http.StatusBadRequest, gin.H{
			"code":    1,
			"message": "白名单IP添加出错:" + err.Error(),
		})
		return
	}
	defer whiteListFile.Close()

	for ip := range pkg.Cfg.Whitelist {
		var err error
		if ones, bits := pkg.Cfg.Whitelist[ip].Mask.Size(); bits == 32 && ones == 32 { // 地址为IPv4且掩码长度为32的，直接写入IP不写掩码
			_, err = whiteListFile.WriteString(pkg.Cfg.Whitelist[ip].IP.String() + "\n")
		} else {
			_, err = whiteListFile.WriteString(ip + "\n")
		}
		if err != nil {
			logrus.Errorf("白名单 %v 写入出错: %v", ip, err.Error())
			continue
		}
	}
	logrus.Infof("白名单删除成功")
	c.JSON(http.StatusOK, gin.H{
		"code":    0,
		"message": "success:",
	})
}

// 查询黑名单
func FindFilterBlackListHandler() {

}

// 添加黑名单
func CreateFilterBlack() {

}

// 删除黑名单
func DeleteFilterBlack() {

}
