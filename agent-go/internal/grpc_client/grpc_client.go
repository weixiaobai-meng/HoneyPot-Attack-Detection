package grpc_client

import (
	"errors"
	"systemwire/agent/internal/agent"
	"systemwire/agent/internal/config"
	pb "systemwire/agent/proto"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

type GRPCClient struct {
	Conn   *grpc.ClientConn
	Client pb.AgentServiceClient
}

func NewGRPCClient(cfg *config.Config) (*pb.AgentServiceClient, error) {
	var conn *grpc.ClientConn // 创建grpc连接
	var err error
	retry := func() { // 重连函数
		// a.Logger.Error("Error to close connection ...")
		if conn != nil {
			if err := conn.Close(); err != nil {
				return
			}
		}
		time.Sleep(5 * time.Second)
		// a.Logger.Info("Try to reconnect ...")
	}
	if cfg.TLS.Enable { // 启用TLS
		// 创建证书
		err := cfg.TLS.CreateDoubleCredentials()
		if err != nil {
			// Logger.Errorf("创建证书失败: %v", err)
			return nil, err
		}

		// 在rpc请求中设置元字段（在请求头加入token，服务端会进行认证）
		metaToken := &agent.Authentication{
			Token: cfg.Token,
		}
		// 发起连接
		conn, err = grpc.NewClient(cfg.ServerAddress, grpc.WithTransportCredentials(*cfg.TLS.Creds), grpc.WithPerRPCCredentials(metaToken))
	} else { // 不启用TLS
		conn, err = grpc.NewClient(cfg.ServerAddress, grpc.WithTransportCredentials(insecure.NewCredentials()))
	}
	if err != nil {
		retry() // 断开连接
		return nil, errors.New("连接失败" + err.Error())
	}
	// Setup connection and client...
	client := pb.NewAgentServiceClient(conn)
	return &client, nil
}

func (g *GRPCClient) Disconnect() {
	g.Conn.Close()
}
