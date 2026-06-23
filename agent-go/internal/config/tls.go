package config

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"google.golang.org/grpc/credentials"
	"os"
	"systemwire/agent/pkg"
)

type TLSConfig struct {
	Enable         bool   // TLS开关
	AuthType       int    // 认证方式(single/double)
	ServerCertPath string // 服务端证书路径
	ClientCertPath string // 客户端证书路径
	ClientKeyPath  string // 客户端密钥路径
	CACertPath     string // CA路径
	ServerName     string // 服务器名/域名，申请证书时填写的域名"[alt_names]"
	Creds          *credentials.TransportCredentials
}

// CreateDoubleCredentials 创建TransportCredentials
func (t *TLSConfig) CreateDoubleCredentials() error {
	var creds credentials.TransportCredentials
	var err error
	if t.AuthType == 1 {
		// 单向认证：只对服务端进行
		// 读取服务端证书
		creds, err = credentials.NewClientTLSFromFile(t.ServerCertPath, "*.cfly.top")
		if err != nil {
			return err
		}
	} else {
		// 双向认证：服务端对客户端认证+客户端对服务端认证
		// 加载客户端证书和私钥
		clientKeyPair, err := tls.LoadX509KeyPair(t.ClientCertPath, t.ClientKeyPath)
		if err != nil {
			return err
		}

		// 加载CA证书
		caCert, err := os.ReadFile(t.CACertPath)
		if err != nil {
			return err
		}
		caCertPool := x509.NewCertPool()
		caCertPool.AppendCertsFromPEM(caCert)

		// 配置 gRPC 的TLS认证
		creds = credentials.NewTLS(&tls.Config{
			Certificates:       []tls.Certificate{clientKeyPair},
			RootCAs:            caCertPool,
			InsecureSkipVerify: false, // 不允许跳过认证
			ServerName:         "*.cfly.top",
		})
	}

	t.Creds = &creds

	return nil
}

// LoadTLSConfig 加载TLS配置
func LoadTLSConfig(config *Config) (*TLSConfig, error) {

	tlsConfig := &TLSConfig{}

	// 读取配置文件
	err := tlsConfig.loadTlsConfig()
	if err != nil {
		return nil, err
	}

	// 检查证书和私钥文件
	if err := tlsConfig.Check(); err != nil {
		return nil, err
	}

	if err := tlsConfig.CreateDoubleCredentials(); err != nil {
		return nil, err
	}

	return tlsConfig, nil
}

// Check 检查密钥
func (t *TLSConfig) Check() error {
	// 检查证书
	basePath, err := os.Executable() // 获取可执行文件路径
	if err != nil {
		return fmt.Errorf("无法获取可执行文件路径: %w", err)
	}
	basePath = ""
	fmt.Println(basePath)

	// 检查所有必要文件是否存在
	paths := map[string]string{
		"ServerCertPath": t.ServerCertPath,
		"ClientCertPath": t.ClientCertPath,
		"ClientKeyPath":  t.ClientKeyPath,
		"CACertPath":     t.CACertPath,
	}

	// 检查服务端证书是否存在
	for name, path := range paths {
		if err := pkg.CheckFileExists(path); err != nil {
			return fmt.Errorf("%s文件不存在, %w", name, err)
		}
	}

	return nil
}

// 加载tls配置信息
func (t *TLSConfig) loadTlsConfig() error {
	// 配置文件的必须字段
	mustKey := map[string]bool{
		"Enable":         true,
		"AuthType":       true,  // 认证方式：1表示单项，2表示双向
		"ServerCertPath": false, // 服务端证书路径
		"ClientCertPath": false, // 客户端证书路径
		"ClientKeyPath":  false, // 客户端密钥路径
		"CACertPath":     false, // CA路径
		"ServerName":     true,  // 服务器名/域名，申请证书时填写的域名"[alt_names]"
	}

	// 读取agent配置块
	tlsSection, err := cfgFile.GetSection("TLS")
	if err != nil {
		return errors.New("读取TLS配置块失败: " + err.Error())
	}
	for key, isMust := range mustKey {
		value, err := tlsSection.GetKey(key)
		if err != nil {
			return err
		}
		if isMust && (value == nil || value.String() == "") {
			return errors.New("配置缺失：" + key)
		}
	}

	t.Enable = tlsSection.Key("Enable").MustBool()
	t.AuthType = tlsSection.Key("AuthType").MustInt()
	t.ServerCertPath = tlsSection.Key("ServerCertPath").MustString("ssl/server.crt") // 每配置则使用默认路径
	t.ClientCertPath = tlsSection.Key("ClientCertPath").MustString("ssl/client.crt")
	t.ClientKeyPath = tlsSection.Key("ClientKeyPath").MustString("ssl/client.key")
	t.CACertPath = tlsSection.Key("CACertPath").MustString("ssl/ca.crt")
	t.ServerName = tlsSection.Key("ServerName").MustString("")

	return nil
}
