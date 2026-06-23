package agent

import (
	"context"
	"errors"
	"fmt"
	"log"
	"os"
	"os/signal"
	"runtime"
	"sync"
	"syscall"
	"systemwire/agent/internal/account"
	"systemwire/agent/internal/config"
	"systemwire/agent/internal/models"
	"systemwire/agent/internal/monitor"
	"systemwire/agent/pkg"
	pb "systemwire/agent/proto"
	"time"

	"github.com/sirupsen/logrus"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

type Agent struct {
	cfg       *config.Config        // 配置
	Logger    *logrus.Logger        // 日志器
	rpcClient pb.AgentServiceClient // rpc客户端
	hostInfo  *models.HostInfo      // 主机信息

	// 蜜点组件
	monitor         monitor.Monitor         // 监控器
	accountDeployer account.AccountDeployer // 账号部署器
	// 命令部署器
	// 进程部署器
}

func NewAgent(cfg *config.Config, token string) *Agent {
	// 创建并启动文件监控
	agent := &Agent{}
	agent.cfg = cfg
	agent.Logger = config.NewLogger(logrus.InfoLevel, cfg.LogPath)

	// 创建诱饵监控器
	switch runtime.GOOS {
	case "windows":
		agent.monitor = monitor.NewInotifyMonitor(nil)
	case "linux":
		agent.monitor = monitor.NewAuditdMonitor(nil)
	default:
		agent.Logger.Error("不支持的监控类型: " + agent.cfg.MonitorType)
	}

	// 创建账号部署器
	agent.accountDeployer = *account.NewAccountDeployer()
	return agent
}

// Start 启动客户端
func (a *Agent) Start() {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	signalChan := make(chan os.Signal, 1)
	signal.Notify(signalChan, syscall.SIGINT, syscall.SIGTERM)

	var err error

	// 初始化主机信息
	hostInfo, err := models.NewHost()
	if err != nil {
		a.Logger.Errorf("初始化失败: %v", err)
		return
	}
	a.hostInfo = hostInfo
	hostinfoMap := hostInfo.ToMap()
	a.Logger.Infof("主机信息: %v", hostinfoMap)

	// 创建grpc连接
	var conn *grpc.ClientConn

	retry := func() { // 重连函数
		a.Logger.Error("Error to close connection ...")
		if conn != nil {
			if err := conn.Close(); err != nil {
				return
			}
		}
		time.Sleep(5 * time.Second)
		a.Logger.Info("Try to reconnect ...")
	}

	// 建立连接、接收命令、执行命令
	for {
		// 建立连接
		conn, err = a.createGRPCConnection()
		if err != nil {
			retry()  // 断开连接
			continue // 重启配置并发起连接
		}

		// 设置RPC客户端
		a.rpcClient = pb.NewAgentServiceClient(conn)
		defer conn.Close()

		// 创建并启动文件监控
		a.monitor.SetRPCClient(a.rpcClient)
		err := a.monitor.Start(ctx)
		if err != nil {
			a.Logger.Fatalf("监控启动出错: %v", err)
			cancel()
			return
		}

		// 向服务端注册
		registed := a.registerHost(ctx, a.rpcClient)
		if !registed {
			cancel()
			return // 注册失败退出程序
		}

		// 启动状态上报（持续）
		restartChan := make(chan bool)
		go func() {
			if err := a.reportStatus(ctx, a.rpcClient); err != nil {
				restartChan <- true
			}
		}()
		// 请求命令（持续）
		recCmd, err := a.rpcClient.RequestCmd(ctx, hostInfo.GetHostPb()) // 流式RPC：不断接收命令
		if err != nil {
			a.Logger.Fatalf("接收命令失败: %v", err)
			cancel()
			return
		}

		// 接收并执行命令
		go a.receiveCmds(ctx, recCmd)

		select {
		case <-restartChan:
			a.Logger.Errorf("状态上报失败: %v，准备重连...", err)
			cancel()                                               // 取消当前上下文
			ctx, cancel = context.WithCancel(context.Background()) // 创建新的上下文
		case <-signalChan:
			a.Logger.Infof("正在退出...")
			cancel() // 触发上下文取消，关闭所有任务、协程
			return   // 退出
		}
	}
}

// 创建连接
func (a *Agent) createGRPCConnection() (*grpc.ClientConn, error) {
	var conn *grpc.ClientConn
	var err error

	if a.cfg.TLS.Enable {
		// 启用 TLS
		err = a.cfg.TLS.CreateDoubleCredentials()
		if err != nil {
			return nil, fmt.Errorf("创建证书失败: %v", err)
		}

		metaToken := &Authentication{Token: a.cfg.Token}
		conn, err = grpc.NewClient(
			a.cfg.ServerAddress,
			grpc.WithTransportCredentials(*a.cfg.TLS.Creds),
			grpc.WithPerRPCCredentials(metaToken),
		)
	} else {
		// 无 TLS
		conn, err = grpc.NewClient(
			a.cfg.ServerAddress,
			grpc.WithTransportCredentials(insecure.NewCredentials()),
		)
	}

	if err != nil {
		return nil, fmt.Errorf("gRPC 连接失败: %v", err)
	}

	return conn, nil
}

// 注册主机信息
func (a *Agent) registerHost(ctx context.Context, client pb.AgentServiceClient) bool {
	// 创建带超时的上下文，但保留外部上下文的取消能力
	host := a.hostInfo.GetHostPb()
	regCounter := 0
	reconnectInterval := 10 // 重连时间间隔
	reconnectLimit := 0     // 重连次数限制：0表示无限制
	for {
		select {
		case <-ctx.Done(): // 如果接收到外部上下文取消信号，立即退出
			// logger.Info("收到上下文取消信号，停止注册")
			return false
		default:
			ctxReq, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()

			fb, err := client.RegisterHost(ctxReq, host)
			if err != nil || !fb.Successful {
				log.Printf("注册主机信息出错: %v", err)
				if fb != nil {
					log.Printf("feedback: %v", fb.Message)
				}
				regCounter++ // 重连计数器+1
				if reconnectLimit == 0 || regCounter <= reconnectLimit {
					a.Logger.Errorf("正在尝试重连...")
					time.Sleep(time.Second * time.Duration(reconnectInterval))
					continue
				} else {
					a.Logger.Errorf("重试次数超过限制，注册失败")
					return false
				}
			}
			return true // 注册成功
		}
	}

}

// 上报状态
func (a *Agent) reportStatus(ctx context.Context, client pb.AgentServiceClient) error {
	ticker := time.NewTicker(a.cfg.ReportInterval) // 计时器
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done(): // 监听上下文的取消信号
			// logger.Info("收到停止信号，停止状态上报")
			return nil // 退出循环，停止状态上报
		case <-ticker.C: // 阻塞等待计时器激活         // 阻塞等待计时器激活}
			// 上报状态
			ctxReq, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()

			// TODO:获取资源信息
			var state *pb.State
			if a.cfg.RealTimeUpdate {
				info, err := pkg.GetStateInfo()
				if err != nil {
					a.Logger.Errorf("State get error, %v", err)
					continue
				}
				state = &pb.State{ // 实例化State Message
					Cpu:     info.Cpu,
					Memory:  info.Memory,
					Disk:    info.Disk,
					Network: info.Networt,
					Io:      info.Io,
					Load:    info.Load,
					Time:    info.Time, //时间戳
				}
			} else {
				state = &pb.State{}
			}

			_, err := client.ReprotState(ctxReq, state)
			if err != nil {
				log.Printf("状态上报失败: %v", err)
				return err
			} else {
				a.Logger.Info("状态上报成功")
			}
		}
	}
}

// 接收命令
func (a *Agent) receiveCmds(ctx context.Context, cmds pb.AgentService_RequestCmdClient) error {
	var err error
	var wg sync.WaitGroup
	subCtx, cancal := context.WithCancel(ctx)
	defer cancal()

	for {
		select {
		case <-ctx.Done():
			cancal()
			// TODO:关闭流
			return errors.New("停止接收命令")
		default:
			var cmd *pb.Cmd

			// 接收命令
			cmd, err = cmds.Recv()
			if err != nil {
				return err
			}
			if cmd.Id == 0 {
				a.Logger.Infof("收到心跳检测")
			} else {
				a.Logger.Infof("接收到命令 ID:%v - TYPE:%v - DATA:%v", cmd.Id, cmd.Type, cmd.Data)
			}

			// 执行命令
			go func() {
				defer wg.Done()
				a.doCmd(subCtx, cmd) // 异步执行命令
			}()
			wg.Add(1)
		}
	}
}

// 执行命令
func (a *Agent) doCmd(ctx context.Context, cmd *pb.Cmd) {
	var err error
	result := &pb.CmdResult{} // 命令执行结果消息体
	start := time.Now()       // 记录开始时间
	// 根据命令类型执行命令
	switch cmd.GetType() {
	case models.CmdBeat:
		// Nothing
	case models.CmdTypeAddPath:
		err = a.handlerAddPathCmd(cmd) // 添加监控路径
	case models.CmdTypeDelPath:
		err = a.handlerDelPathCmd(cmd) // 删除监控路径
	case models.CmdTypeAddAccount:
		err = a.handlerAddAccount(cmd) // 部署账户蜜点
	case models.CmdTypeSendFile:
		err = a.handlerSendFile(cmd) // 下发文件
	case models.CmdTypeDeployFileHoneypot:
		err = a.handlerDeployFileHoneypot(cmd) // 部署文件蜜点
	case models.CmdTypeDeployParasitic:
		err = a.handlerDeployParasitic(cmd) // 部署寄生蜜点
	default:
		a.Logger.Infof("未知命令: %v", cmd)
	}

	// 发送执行结果
	duration := time.Since(start)              // 计算执行时间差
	result.Id = cmd.Id                         // 对应的命令ID
	result.Type = cmd.Type                     // 命令类型
	result.Delay = float32(duration.Seconds()) // 执行时间
	if err != nil {
		result.Successful = false // 执行不成功
		result.Data = err.Error()
	} else {
		result.Successful = true // 执行成功
		result.Data = ""
	}
	if _, err := a.rpcClient.ReturnCmdResult(ctx, result); err != nil {
		a.Logger.Error("发送命令结果失败:", err)
	}
}
