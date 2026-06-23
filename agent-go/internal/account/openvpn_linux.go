//go:build linux
// +build linux

package account

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

// VPN 配置结构体
type VPNConfig struct {
	RemoteIP string
}

// 创建虚假的 VPN 配置
func (v *VPNConfig) createFakeConfig(path string) (string, error) {
	templateFile := "config/templates/vpn.txt"

	templateData, err := os.ReadFile(templateFile)
	if err != nil {
		return "", fmt.Errorf("error reading template file %s: %v", templateFile, err)
	}

	// 创建临时目录
	tmpDir, err := os.MkdirTemp(path, "openvpn_config_*")
	if err != nil {
		return "", fmt.Errorf("error creating temporary directory: %v", err)
	}

	// 生成虚假证书和密钥
	err = v.generateFakeCertificates(tmpDir)
	if err != nil {
		return "", fmt.Errorf("error generating fake certificates: %v", err)
	}

	// 创建配置文件
	configPath := filepath.Join(tmpDir, "公司-卫生.ovpn")
	configFile, err := os.Create(configPath)
	if err != nil {
		return "", fmt.Errorf("error creating config file: %v", err)
	}
	defer configFile.Close()

	// 替换模板中的IP地址和证书路径
	configContent := strings.ReplaceAll(string(templateData), "{{.RemoteIP}}", v.RemoteIP)
	configContent = strings.ReplaceAll(configContent, "ca.crt", filepath.Join(tmpDir, "ca.crt"))
	configContent = strings.ReplaceAll(configContent, "client.crt", filepath.Join(tmpDir, "client.crt"))
	configContent = strings.ReplaceAll(configContent, "client.key", filepath.Join(tmpDir, "client.key"))

	_, err = configFile.Write([]byte(configContent))
	if err != nil {
		return "", fmt.Errorf("error writing config file: %v", err)
	}

	return configPath, nil
}

// 生成虚假的证书和密钥
func (v *VPNConfig) generateFakeCertificates(dir string) error {
	// 生成 CA 私钥
	caKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return fmt.Errorf("failed to generate CA key: %v", err)
	}

	caTemplate := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			Organization: []string{"OpenVPN-CA"},
			Country:      []string{"US"},
			Province:     []string{"CA"},
			Locality:     []string{"OpenVPN"},
			CommonName:   "OpenVPN CA",
		},
		NotBefore:             time.Now().Add(-24 * time.Hour),
		NotAfter:              time.Now().Add(3650 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLen:            0,
		MaxPathLenZero:        true,
	}

	caCertDER, err := x509.CreateCertificate(rand.Reader, &caTemplate, &caTemplate, &caKey.PublicKey, caKey)
	if err != nil {
		return fmt.Errorf("failed to create CA certificate: %v", err)
	}

	caCertFile, err := os.Create(filepath.Join(dir, "ca.crt"))
	if err != nil {
		return fmt.Errorf("failed to create ca.crt file: %v", err)
	}
	defer caCertFile.Close()

	err = pem.Encode(caCertFile, &pem.Block{Type: "CERTIFICATE", Bytes: caCertDER})
	if err != nil {
		return fmt.Errorf("failed to write CA certificate: %v", err)
	}

	// 生成客户端私钥
	clientKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return fmt.Errorf("failed to generate client key: %v", err)
	}

	clientTemplate := x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject: pkix.Name{
			Organization: []string{"OpenVPN-Client"},
			Country:      []string{"US"},
			Province:     []string{"CA"},
			Locality:     []string{"OpenVPN"},
			CommonName:   "client",
		},
		NotBefore:   time.Now().Add(-24 * time.Hour),
		NotAfter:    time.Now().Add(3650 * 24 * time.Hour),
		KeyUsage:    x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		SubjectKeyId: []byte{
			1, 2, 3, 4, 5, 6, 7, 8, 9, 10,
			11, 12, 13, 14, 15, 16, 17, 18, 19, 20,
		},
	}

	clientCertDER, err := x509.CreateCertificate(rand.Reader, &clientTemplate, &caTemplate, &clientKey.PublicKey, caKey)
	if err != nil {
		return fmt.Errorf("failed to create client certificate: %v", err)
	}

	clientCertFile, err := os.Create(filepath.Join(dir, "client.crt"))
	if err != nil {
		return fmt.Errorf("failed to create client.crt file: %v", err)
	}
	defer clientCertFile.Close()

	err = pem.Encode(clientCertFile, &pem.Block{Type: "CERTIFICATE", Bytes: clientCertDER})
	if err != nil {
		return fmt.Errorf("failed to write client certificate: %v", err)
	}

	clientKeyFile, err := os.Create(filepath.Join(dir, "client.key"))
	if err != nil {
		return fmt.Errorf("failed to create client.key file: %v", err)
	}
	defer clientKeyFile.Close()

	clientKeyDER := x509.MarshalPKCS1PrivateKey(clientKey)
	err = pem.Encode(clientKeyFile, &pem.Block{Type: "RSA PRIVATE KEY", Bytes: clientKeyDER})
	if err != nil {
		return fmt.Errorf("failed to write client key: %v", err)
	}

	return nil
}

// 查找 OpenVPN 配置文件路径
func (v *VPNConfig) FindOpenVPNConfigPaths() (string, error) {
	if path, found := v.checkDefaultPaths(); found {
		return path, nil
	}

	drives := []string{"/etc/openvpn", filepath.Join(os.Getenv("HOME"), ".openvpn"), "/mnt", "/media"}
	const (
		timeout     = 20 * time.Second
		concurrency = 2
	)

	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	resultChan := make(chan string, len(drives))
	sem := make(chan struct{}, concurrency)

	for _, d := range drives {
		go func(drive string) {
			sem <- struct{}{}
			defer func() { <-sem }()

			paths, _ := v.findOpenVPNSessions(drive)
			for _, path := range paths {
				if v.hasOvpnFile(path) {
					resultChan <- path
					return
				}
			}
		}(d)
	}

	select {
	case path := <-resultChan:
		fmt.Println("Found valid OpenVPN config directory:", path)
		return path, nil
	case <-ctx.Done():
		return "", fmt.Errorf("扫描超时，未找到有效路径")
	}
}

// 使用 find 查找 OpenVPN 配置
func (v *VPNConfig) findOpenVPNSessions(basePath string) ([]string, error) {
	cmd := exec.Command("find", basePath, "-type", "d", "-name", "config", "-path", "*/OpenVPN/*")
	var out bytes.Buffer
	cmd.Stdout = &out
	err := cmd.Run()
	if err != nil {
		return nil, fmt.Errorf("find command failed: %v", err)
	}

	paths := strings.Split(strings.TrimSpace(out.String()), "\n")
	if len(paths) == 0 || paths[0] == "" {
		return nil, nil
	}
	return paths, nil
}

// 检查默认安装路径
func (v *VPNConfig) checkDefaultPaths() (string, bool) {
	defaultPaths := []string{
		"/etc/openvpn",
		filepath.Join(os.Getenv("HOME"), ".openvpn"),
	}

	for _, path := range defaultPaths {
		if v.isDirectoryExists(path) && v.hasOvpnFile(path) {
			fmt.Printf("通过默认路径找到配置目录: %s\n", path)
			return path, true
		}
	}
	return "", false
}

// 检查目录是否存在
func (v *VPNConfig) isDirectoryExists(path string) bool {
	info, err := os.Stat(path)
	if err != nil {
		if os.IsNotExist(err) {
			return false
		}
		fmt.Println("Error:", err)
		return false
	}
	return info.IsDir()
}

// 检查目录下是否有 .ovpn 文件
func (v *VPNConfig) hasOvpnFile(path string) bool {
	err := filepath.Walk(path, func(fpath string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if !info.IsDir() && strings.HasSuffix(info.Name(), ".ovpn") {
			return fmt.Errorf("found .ovpn file")
		}
		return nil
	})
	return err != nil
}
