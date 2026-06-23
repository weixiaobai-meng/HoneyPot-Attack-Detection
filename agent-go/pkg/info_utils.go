package pkg

import (
	"fmt"
	"net"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/shirou/gopsutil/cpu"
	"github.com/shirou/gopsutil/disk"
	"github.com/shirou/gopsutil/load"
	"github.com/shirou/gopsutil/mem"
	gnet "github.com/shirou/gopsutil/net"
)

type StateInfo struct {
	Cpu     float64
	Memory  float64
	Disk    float64
	Networt float64
	Io      float64
	Load    float64
	Time    int64
}

func GetHostIp() string {
	conn, err := net.Dial("udp", "8.8.8.8:53")
	if err != nil {
		fmt.Println("get current host ip err: ", err)
		return ""
	}
	addr := conn.LocalAddr().(*net.UDPAddr)
	ip := strings.Split(addr.String(), ":")[0]
	return ip
}

// 获取CPU信息
func GetCpuInfo() (map[string]interface{}, error) {
	cpuInfo := make(map[string]interface{})

	count, err := cpu.Counts(false) // CPU物理内核数量
	if err != nil {
		return nil, err
	}

	percent, err := cpu.Percent(time.Second*2, false) // CPU使用率
	if err != nil {
		return nil, err
	}

	memSize, err := mem.VirtualMemory() // 内存大小
	if err != nil {
		return nil, err
	}
	// 获取磁盘分区信息
	diskPartitions, err := disk.Partitions(true)
	if err != nil {
		fmt.Printf("Failed to get disk partitions: %v", err)
		return nil, err
	}
	fmt.Printf("Disk partitions: %+v\n", diskPartitions)
	for _, partition := range diskPartitions {
		// 获取每个磁盘分区的使用情况
		usage, err := disk.Usage(partition.Mountpoint)
		if err != nil {
			fmt.Printf("Failed to get disk usage for %s: %v", partition.Mountpoint, err)
			continue
		}
		fmt.Printf("%s usage: %+v\n", partition.Mountpoint, usage)
	}
	cpuInfo["count"] = count
	cpuInfo["percent"] = percent
	cpuInfo["memSize"] = memSize

	return cpuInfo, nil
}

// 获取State信息
func GetStateInfo() (*StateInfo, error) {
	state := &StateInfo{}

	// 时间戳
	timeStamp := time.Now().Unix()

	// CPU信息
	cpuInfo, err := cpu.Percent(time.Second*2, false) // CPU使用率
	if err != nil {
		return nil, err
	}

	// 内存信息
	memInfo, err := mem.VirtualMemory() // 内存大小
	if err != nil {
		return nil, err
	}

	// 硬盘信息
	diskParts, err := disk.Partitions(false)
	if err != nil {
		return nil, err
	}
	partition := diskParts[0] // 暂时只获取第一个盘的信息
	diskUsed, err := disk.Usage(partition.Mountpoint)
	if err != nil {
		return nil, err
	}
	diskUsage := diskUsed.UsedPercent

	// 网络信息
	netInfo, err := gnet.IOCounters(true)
	if err != nil {
		return nil, err
	}
	network_out := float64(netInfo[0].BytesSent) / 1024 / 1024

	// io信息

	// 系统负载
	loadInfo, err := load.Avg()
	if err != nil {
		return nil, err
	}

	state.Cpu = cpuInfo[0]                             // CPU使用率
	state.Memory = float64(memInfo.Used / 1024 / 1024) // 已使用内存大小单位M
	state.Disk = diskUsage
	state.Networt = network_out
	state.Io = 0
	state.Load = float64(loadInfo.Load1)
	state.Time = timeStamp

	return state, nil
}

// IsValidServerAddress 检查字符串是否为合法的 ip:port 格式
func IsValidServerAddress(address string) bool {
	// 分割 ip 和 port
	parts := strings.Split(address, ":")
	if len(parts) != 2 {
		return false
	}

	// 验证 IP 部分
	ip := parts[0]
	if net.ParseIP(ip) == nil && ip != "localhost" {
		return false
	}

	// 验证端口部分
	port := parts[1]
	portNumber, err := strconv.Atoi(port)
	if err != nil || portNumber < 1 || portNumber > 65535 {
		return false
	}

	return true
}

// CheckFileExists 检查文件是否存在
func CheckFileExists(filePath string) error {
	_, err := os.Stat(filePath)
	if os.IsNotExist(err) {
		return err
	}
	return nil
}
