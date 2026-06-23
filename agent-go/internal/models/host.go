package models

import (
	"errors"
	"os"
	"runtime"
	"systemwire/agent/pkg"
	pb "systemwire/agent/proto"
)

type HostInfo struct {
	hostname string
	id       string // 主机ID
	ip       string // IP地址
	opeSys   string // 操作系统
}

// NewHost 初始化关联的Host
func NewHost() (*HostInfo, error) {
	var err error

	// 获取主机的用户名
	hostname, err := os.Hostname()
	if err != nil {
		return nil, errors.New("获取主机名失败")
	}

	// id := uuid.New().String()	// 获取主机ID:uuid
	id := "c89cf3ce-1810-49e2-834f-ca83e4872121" // TEST:id
	ip := pkg.GetHostIp()                        // 获取主机IP
	opeSys := runtime.GOOS

	return &HostInfo{
		hostname: hostname,
		id:       id,
		ip:       ip,
		opeSys:   opeSys,
	}, nil
}

// ToMap 获取Host信息
func (a *HostInfo) ToMap() map[string]string {
	info := map[string]string{
		"hostname": a.hostname,
		"id":       a.id,
		"ip":       a.ip,
		"opeSys":   a.opeSys,
	}
	return info
}

// GetHostPb pb消息体
func (a *HostInfo) GetHostPb() *pb.Host {
	return &pb.Host{
		Hostname: a.hostname,
		Id:       a.id,
		Ip:       a.ip,
		Os:       a.opeSys,
	}
}
