package models

// 命令类型
const (
	_                       = iota // 自动递增
	CmdBeat                        // 心跳检测
	CmdTypeAddPath                 // 添加监控路径
	CmdTypeDelPath                 // 删除监控路径
	CmdTypeAddAccount              // 添加账户蜜点
	CmdTypeSendFile                // 文件下发
	CmdTypeDeployFileHoneypot      // 部署文件蜜点
	CmdTypeDeployParasitic         // 部署寄生蜜点
)
