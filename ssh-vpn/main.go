package main

import (
	"bytes"
	"crypto/hmac"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"io"
	"log"
	"math/rand"
	"net"
	"net/http"
	"os"

	"github.com/sirupsen/logrus"
	"golang.org/x/crypto/ssh"
)

const appName = "sshd"

// --- 1. 远程日志发送模块 (发送给你的 Go 后端) ---
type RemoteWriter struct {
	TargetURL string
}

func (w *RemoteWriter) Write(p []byte) (n int, err error) {
	if w.TargetURL == "" {
		return len(p), nil
	}
	// 复制数据，防止由于异步导致的数据竞争
	data := make([]byte, len(p))
	copy(data, p)

	// 异步发送：确保蜜罐本身的 SSH 响应速度不受网络影响
	go func(logData []byte) {
		// 这里会发送标准的 JSON 数据，Content-Type: application/json
		resp, err := http.Post(w.TargetURL, "application/json", bytes.NewBuffer(logData))
		if err != nil {
			// 如果你的 Go 后端没启动，这里会报错，但不会导致蜜罐崩溃
			// log.Printf("发送日志失败: %v", err)
			return
		}
		defer resp.Body.Close()
	}(data)

	return len(p), nil
}

// ---------------------------

var errAuthenticationFailed = errors.New(":)")

var commonFields = logrus.Fields{
	"destinationServicename": "sshd",
	"product":                "OpenSSH",
}

// 主日志 (用于发送给后端)
var logger = logrus.WithFields(commonFields)

// 独立密码文件日志 (本地备份用)
var passwordLogger *logrus.Logger

var (
	sshd_bind      string
	sshd_key_key   string
	vpn_port       string
	remote_log_url string
)

func connLogParameters(conn net.Conn) logrus.Fields {
	src, spt, _ := net.SplitHostPort(conn.RemoteAddr().String())
	dst, dpt, _ := net.SplitHostPort(conn.LocalAddr().String())

	return logrus.Fields{
		"src": src,
		"spt": spt,
		"dst": dst,
		"dpt": dpt,
	}
}

func logParameters(conn ssh.ConnMetadata) logrus.Fields {
	src, spt, _ := net.SplitHostPort(conn.RemoteAddr().String())
	dst, dpt, _ := net.SplitHostPort(conn.LocalAddr().String())

	return logrus.Fields{
		"duser":          conn.User(),
		"src":            src,
		"spt":            spt,
		"dst":            dst,
		"dpt":            dpt,
		"client_version": string(conn.ClientVersion()),
		"server_version": string(conn.ServerVersion()),
	}
}

// 验证密码
func authenticatePassword(conn ssh.ConnMetadata, password []byte) (*ssh.Permissions, error) {
	fields := logrus.Fields{
		"password": string(password),
	}

	// 1. 发送给你的 Go 后端 (通过 RemoteWriter)
	// 同时也会写入本地主日志 ssh_auth_log.json
	logger.WithFields(logParameters(conn)).WithFields(fields).Info("Request with password")

	// 2. 额外写入本地的独立密码文件 (作为双重备份)
	if passwordLogger != nil {
		passwordLogger.WithFields(commonFields).
			WithFields(logParameters(conn)).
			WithFields(fields).
			Info("Request with password")
	}

	return nil, errAuthenticationFailed
}

func authenticateKey(conn ssh.ConnMetadata, key ssh.PublicKey) (*ssh.Permissions, error) {
	fields := logrus.Fields{
		"keytype":     key.Type(),
		"fingerprint": ssh.FingerprintSHA256(key),
	}
	logger.WithFields(logParameters(conn)).WithFields(fields).Info("Request with key")
	return nil, errAuthenticationFailed
}

func HashToInt64(message, key []byte) int64 {
	mac := hmac.New(sha256.New, key)
	mac.Write(message)
	hash := mac.Sum(nil)
	i := binary.LittleEndian.Uint64(hash[:8])
	return int64(i)
}

func getHost(addr string) string {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		logrus.Fatal(err)
	}
	return host
}

func getKey(host string) (*rsa.PrivateKey, error) {
	logrus.WithFields(logrus.Fields{"addr": host}).Debug("Generating host key")

	randomSeed := HashToInt64([]byte(host), []byte(sshd_key_key))
	randomSource := rand.New(rand.NewSource(randomSeed))

	key, err := rsa.GenerateKey(randomSource, 2048)
	if err != nil {
		return key, err
	}
	return key, err
}

var serverVersions = []string{
	"SSH-2.0-OpenSSH_8.9p1",
	"SSH-2.0-OpenSSH_9.3p1",
	"SSH-2.0-OpenSSH_9.6p1",
	"SSH-2.0-OpenSSH_8.4p1",
	"SSH-2.0-dropbear_2022.83",
}

func getServerVersion(host string) string {
	randomSeed := HashToInt64([]byte(host), []byte(sshd_key_key))
	if randomSeed < 0 {
		randomSeed = -randomSeed
	}
	n := int(randomSeed) % len(serverVersions)
	return serverVersions[n]
}

func makeSSHConfig(host string) ssh.ServerConfig {
	config := ssh.ServerConfig{
		PasswordCallback:  authenticatePassword,
		PublicKeyCallback: authenticateKey,
		ServerVersion:     getServerVersion(host),
		MaxAuthTries:      3,
	}

	privateKey, err := getKey(host)
	if err != nil {
		logrus.Panic(err)
	}
	hostPrivateKeySigner, err := ssh.NewSignerFromKey(privateKey)
	if err != nil {
		logrus.Panic(err)
	}
	config.AddHostKey(hostPrivateKeySigner)
	return config
}

func handleConnection(conn net.Conn, config *ssh.ServerConfig) {
	_, _, _, err := ssh.NewServerConn(conn, config)
	if err == nil {
		logrus.Panic("Successful login? why!?")
	}
}

// VPN 监控逻辑
func startVPNMonitor(port string) {
	addr, err := net.ResolveUDPAddr("udp", port)
	if err != nil {
		log.Fatalf("Failed to resolve UDP address: %v", err)
	}

	socket, err := net.ListenUDP("udp", addr)
	if err != nil {
		log.Fatalf("Failed to start VPN monitor: %v", err)
	}
	defer socket.Close()

	log.Printf("Listening for VPN connections on %s", port)

	for {
		buffer := make([]byte, 1024)
		n, clientAddr, err := socket.ReadFromUDP(buffer)
		if err != nil {
			log.Printf("Error reading VPN connection: %v", err)
			continue
		}

		clientData := hex.EncodeToString(buffer[:n])
		// 发送 VPN 探测日志给 Go 后端
		logger.WithFields(logrus.Fields{
			"src":      clientAddr.String(),
			"protocol": "OpenVPN",
			"raw_data": clientData,
		}).Info("VPN connection attempt")
	}
}

func getEnvWithDefault(key, fallback string) string {
	value := os.Getenv(key)
	if value == "" {
		return fallback
	}
	return value
}

func init() {
	logrus.SetFormatter(&logrus.JSONFormatter{})

	// 1. 设置主日志 (写入本地文件 + 发送给远程)
	file, err := os.OpenFile("ssh_auth_log.json", os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0666)
	if err != nil {
		logrus.Fatal(err)
	}

	// 默认直报 systemwire2 账户蜜点告警接口；如需转发到其他平台，可用
	// REMOTE_LOG_URL 环境变量覆盖。
	remote_log_url = getEnvWithDefault("REMOTE_LOG_URL", "http://127.0.0.1:9090/account/alert")

	remoteWriter := &RemoteWriter{
		TargetURL: remote_log_url,
	}

	multiOutput := io.MultiWriter(file, remoteWriter)
	logrus.SetOutput(multiOutput)

	// 2. 设置独立密码日志 (本地备份)
	passFile, err := os.OpenFile("ssh_passwords_only.json", os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0666)
	if err != nil {
		logrus.Fatal("Failed to open password log file:", err)
	}
	passwordLogger = logrus.New()
	passwordLogger.SetOutput(passFile)
	passwordLogger.SetFormatter(&logrus.JSONFormatter{})

	sshd_bind = getEnvWithDefault("SSHD_BIND", ":22")
	sshd_key_key = getEnvWithDefault("SSHD_KEY_KEY", "host-key-seed-2024")
	vpn_port = getEnvWithDefault("VPN_PORT", ":1194")
}

func main() {
	sshConfigMap := make(map[string]ssh.ServerConfig)

	// 启动 VPN 监听
	go func() {
		startVPNMonitor(vpn_port)
	}()

	log.Printf("Starting SSH Honeypot on %s...", sshd_bind)
	log.Printf("Backend URL configured to: %s", remote_log_url)

	socket, err := net.Listen("tcp", sshd_bind)
	if err != nil {
		panic(err)
	}
	for {
		conn, err := socket.Accept()
		if err != nil {
			log.Panic(err)
		}
		logger.WithFields(connLogParameters(conn)).Info("Connection")
		host := getHost(conn.LocalAddr().String())

		config, existed := sshConfigMap[host]
		if !existed {
			config = makeSSHConfig(host)
			sshConfigMap[host] = config
		}
		go handleConnection(conn, &config)
	}
}
