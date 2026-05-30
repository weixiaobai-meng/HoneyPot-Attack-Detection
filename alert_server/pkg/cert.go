package pkg

import (
	"crypto/tls"
	"os"

	"github.com/sirupsen/logrus"
)

var (
	certPath = "ssl/cert.pem" // 证书路径
	keyPath  = "ssl/key.pem"  // 私钥路径
)

func LoadCert() (*tls.Certificate, error) {
	CreateDirIfNotExist("ssl")

	// 检查 SSL 文件夹和证书文件是否存在
	if _, err := os.Stat(certPath); os.IsNotExist(err) {
		logrus.Error("[Server] 缺少证书(cert.pem)文件！")
		return nil, err
	}
	if _, err := os.Stat(keyPath); os.IsNotExist(err) {
		logrus.Error("[Server] 缺少私钥(key.pem)文件！")
		return nil, err
	}

	if _, err := os.Stat(keyPath); os.IsNotExist(err) {
		logrus.Error("[Server] ssl文件夹不存在，已自动创建，请添加证书(cert.pem)和私钥(key.pem)文件！")
		return nil, err
	}

	cert, err := tls.LoadX509KeyPair(certPath, keyPath) // 加载SSL证书
	if err != nil {
		// log.Fatalf("Failed to load key pair: %s", err)
		logrus.Error("[Server] SSL证书加载失败")
		logrus.Error(err)
		return nil, err
	}
	return &cert, nil
}

// 配置tls配置
func LoadTlsConfig(cert tls.Certificate) *tls.Config {
	// 配置TLS
	return &tls.Config{
		Certificates: []tls.Certificate{cert},
	}
}
