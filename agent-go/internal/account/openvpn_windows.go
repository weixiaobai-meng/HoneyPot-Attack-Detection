//go:build windows
// +build windows

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
	// 读取模板文件内容
	templateFile := "config/templates/vpn.txt" // 模板文件放在 templates 文件夹中
	templateData, err := os.ReadFile(templateFile)
	if err != nil {
		return "", fmt.Errorf("error reading template file %s: %v", templateFile, err)
	}

	// 创建临时目录用于存放配置和证书文件
	tmpDir, err := os.MkdirTemp(path, "openvpn_config_*")
	if err != nil {
		return "", fmt.Errorf("error creating temporary directory: %v", err)
	}

	// 生成虚假证书和密钥
	err = v.generateFakeCertificates(tmpDir)
	if err != nil {
		return "", fmt.Errorf("error generating fake certificates: %v", err)
	}

	// 生成唯一文件名，避免覆盖
	timestamp := time.Now().Format("20060102150405") // 获取当前时间戳
	configPath := filepath.Join(tmpDir, fmt.Sprintf("公司-高梦-%s.ovpn", timestamp))
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

	// 处理路径中的反斜杠，将其转换为双反斜杠
	configContent = strings.ReplaceAll(configContent, "\\", "\\\\")

	_, err = configFile.Write([]byte(configContent))
	if err != nil {
		return "", fmt.Errorf("error writing config file: %v", err)
	}

	// 返回配置文件路径
	return configPath, nil
}

// 测试生成的配置是否被OpenVPN接受
func (v *VPNConfig) TestConfigValidity(configPath string) (bool, error) {
	// 使用 openvpn --config 测试配置文件是否有效
	cmd := exec.Command("openvpn", "--config", configPath, "--verb", "3", "--connect-timeout", "5")
	var stderr bytes.Buffer
	cmd.Stderr = &stderr

	// 设置超时
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	cmd = exec.CommandContext(ctx, "openvpn", "--config", configPath, "--verb", "3", "--connect-timeout", "5")
	cmd.Stderr = &stderr

	err := cmd.Run()
	output := stderr.String()

	// 分析输出以确定是否通过了证书验证阶段
	if strings.Contains(output, "Certificate verification failed") {
		return false, fmt.Errorf("证书验证失败: %s", output)
	}
	if strings.Contains(output, "TLS Error") {
		return false, fmt.Errorf("TLS错误: %s", output)
	}
	if strings.Contains(output, "Connection timed out") || strings.Contains(output, "Connection refused") {
		// 这是好的！说明通过了证书验证，只是连接不到服务器
		return true, nil
	}

	// 如果没有明显的证书错误，认为是成功的
	return err == nil || strings.Contains(output, "Attempting to establish TCP connection"), nil
}

// 生成虚假的证书和密钥文件
func (v *VPNConfig) generateFakeCertificates(dir string) error {
	// 生成CA私钥
	caKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return fmt.Errorf("failed to generate CA key: %v", err)
	}

	// 创建CA证书模板
	caTemplate := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			Organization: []string{"OpenVPN-CA"},
			Country:      []string{"US"},
			Province:     []string{"CA"},
			Locality:     []string{"OpenVPN"},
			CommonName:   "OpenVPN CA",
		},
		NotBefore:             time.Now().Add(-24 * time.Hour),       // 提前1天，避免时钟偏差
		NotAfter:              time.Now().Add(3650 * 24 * time.Hour), // 10年有效期
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLen:            0,
		MaxPathLenZero:        true,
	}

	// 生成CA证书
	caCertDER, err := x509.CreateCertificate(rand.Reader, &caTemplate, &caTemplate, &caKey.PublicKey, caKey)
	if err != nil {
		return fmt.Errorf("failed to create CA certificate: %v", err)
	}

	// 保存CA证书
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

	// 创建客户端证书模板 - 添加OpenVPN要求的扩展
	clientTemplate := x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject: pkix.Name{
			Organization: []string{"OpenVPN-Client"},
			Country:      []string{"US"},
			Province:     []string{"CA"},
			Locality:     []string{"OpenVPN"},
			CommonName:   "client",
		},
		NotBefore:   time.Now().Add(-24 * time.Hour),       // 提前1天
		NotAfter:    time.Now().Add(3650 * 24 * time.Hour), // 10年有效期
		KeyUsage:    x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		// 添加OpenVPN可能需要的扩展
		SubjectKeyId: []byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20},
	}

	// 生成客户端证书（由CA签名）
	clientCertDER, err := x509.CreateCertificate(rand.Reader, &clientTemplate, &caTemplate, &clientKey.PublicKey, caKey)
	if err != nil {
		return fmt.Errorf("failed to create client certificate: %v", err)
	}

	// 保存客户端证书
	clientCertFile, err := os.Create(filepath.Join(dir, "client.crt"))
	if err != nil {
		return fmt.Errorf("failed to create client.crt file: %v", err)
	}
	defer clientCertFile.Close()

	err = pem.Encode(clientCertFile, &pem.Block{Type: "CERTIFICATE", Bytes: clientCertDER})
	if err != nil {
		return fmt.Errorf("failed to write client certificate: %v", err)
	}

	// 保存客户端私钥
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

// 查找OpenVPN配置文件路径（混合扫描方案）
func (v *VPNConfig) FindOpenVPNConfigPaths() (string, error) {
	// 新增默认路径检查（优先快速通道）
	if path, found := v.checkDefaultPaths(); found {
		return path, nil
	}

	// 获取驱动器列表
	drives, err := GetDriveList()
	if err != nil {
		return "", fmt.Errorf("error getting drive list: %v", err)
	}

	// 智能扫描控制
	const (
		timeout     = 20 * time.Second
		concurrency = 2
	)
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	resultChan := make(chan string, len(drives))
	sem := make(chan struct{}, concurrency)

	// 并行扫描优化
	for _, drive := range drives {
		go func(d string) {
			sem <- struct{}{}
			defer func() { <-sem }()

			// 扫描 OpenVPN 配置目录
			paths, err := v.findOpenVPNSessions(d)
			if err != nil {
				fmt.Printf("Scan %s error: %v\n", d, err)
				return
			}

			// 检查目录中是否包含 .ovpn 文件
			for _, path := range paths {
				if v.hasOvpnFile(path) {
					resultChan <- path
					return
				}
			}
		}(drive)
	}

	// 结果等待
	select {
	case path := <-resultChan:
		fmt.Println("Found valid OpenVPN config directory:", path)
		return path, nil
	case <-ctx.Done():
		return "", fmt.Errorf("扫描超时，未找到有效路径")
	}
}

// 执行 PowerShell 命令查找含有 OpenVPN\config 特定路径
func (v *VPNConfig) findOpenVPNSessions(drive string) ([]string, error) {
	drive = normalizeDrive(drive)
	psCmd := fmt.Sprintf("[Console]::OutputEncoding = [System.Text.Encoding]::UTF8; Get-ChildItem -Path %s -Directory -ErrorAction SilentlyContinue -Recurse | Where-Object { $_.FullName -match 'OpenVPN\\\\config' } | Select-Object -ExpandProperty FullName", drive)
	cmd := exec.Command("powershell", "-Command", psCmd)
	var out bytes.Buffer
	var stderr bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &stderr

	err := cmd.Run()
	if err != nil {
		if stderr.Len() > 0 {
			return nil, fmt.Errorf("PowerShell 执行错误: %v\n%s", err, stderr.String())
		}
	}

	// 解析结果
	output := strings.TrimSpace(out.String())
	if output == "" {
		return nil, nil
	}
	return strings.FieldsFunc(output, func(r rune) bool {
		return r == '\r' || r == '\n'
	}), nil
}

// 检查默认安装路径
func (v *VPNConfig) checkDefaultPaths() (string, bool) {
	defaultPaths := []string{
		filepath.Join(os.Getenv("PROGRAMFILES"), "OpenVPN", "config"),
		filepath.Join(os.Getenv("ProgramFiles(x86)"), "OpenVPN", "config"),
		`C:\OpenVPN\config`,
	}

	for _, path := range defaultPaths {
		if v.isDirectoryExists(path) && v.hasOvpnFile(path) {
			fmt.Printf("通过默认路径找到配置目录: %s\n", path)
			return path, true
		}
	}
	return "", false
}

// 检查给定路径是否存在并且是一个目录
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

func (v *VPNConfig) hasOvpnFile(path string) bool {
	err := filepath.Walk(path, func(fpath string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if !info.IsDir() && strings.HasSuffix(info.Name(), ".ovpn") {
			return fmt.Errorf("found .ovpn file") // 跳出文件遍历
		}
		return nil
	})
	return err != nil // 如果找到 .ovpn 文件，则返回 true
}
