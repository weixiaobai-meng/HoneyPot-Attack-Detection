package tests

import (
	"fmt"
	"testing"
	"time"

	"systemwire/agent/pkg"

	"github.com/shirou/gopsutil/cpu"
	"github.com/shirou/gopsutil/host"
	"github.com/shirou/gopsutil/load"
	"github.com/shirou/gopsutil/mem"
)

func TestGetCpuInfo(t *testing.T) {
	fmt.Println("------------CPU------------")
	info, _ := cpu.Info()
	for _, item := range info {
		fmt.Println(item)
	}
	// CPU利用率
	fmt.Println("------------CPU Percent------------")
	for i := 0; i < 10; i++ {
		time.Sleep(time.Second * 5)
		percent, _ := cpu.Percent(time.Second, false)
		fmt.Println(percent)
	}
	// Load值
	fmt.Println("------------CPU Load------------")
	avg, _ := load.Avg()
	fmt.Println(avg)
}

func TestGetMenInfo(t *testing.T) {
	//显示物理内存信息
	fmt.Println("------------Mem------------")
	memory, _ := mem.VirtualMemory()
	fmt.Printf("Total: %v MB, Used:%v MB,UsedPercent:%.2f%%\n", memory.Total/1024/1024, memory.Used/1024/1024, memory.UsedPercent)
	// 显示交换内存信息
	swapMemory, _ := mem.SwapMemory()
	fmt.Println(swapMemory)

}

func TestGetHostInfo(t *testing.T) {
	bootTime, _ := host.BootTime()
	fmt.Println(bootTime)
	// 显示机器信息
	info, _ := host.Info()
	fmt.Println(info)
	// 显示终端用户
	users, _ := host.Users()
	for _, user := range users {
		fmt.Println(user.User)
	}
}

func TestGet(t *testing.T) {
	pkg.GetCpuInfo()
}
