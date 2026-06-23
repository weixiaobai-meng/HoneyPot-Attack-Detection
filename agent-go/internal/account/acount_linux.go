//go:build linux
// +build linux

package account

import (
	"fmt"
	"math/rand"
	"os"
	"path/filepath"
	"strings"
	"systemwire/agent/internal/config"
	"systemwire/agent/internal/models"
	"time"

	"github.com/sirupsen/logrus"
)

// AccountDeployer handles account honeypot profile deployment.
type AccountDeployer struct {
	Logger *logrus.Logger
}

func NewAccountDeployer() *AccountDeployer {
	loggerObj := config.NewLogger(logrus.InfoLevel, "log/accouter.log")
	return &AccountDeployer{Logger: loggerObj}
}

func (a *AccountDeployer) DeployXshellConfig(cfg models.ShellCfg) error {
	return fmt.Errorf("DeployXshellConfig is not supported on Linux")
}

func (a *AccountDeployer) DeployFinalshellConfig(cfg models.ShellCfg) error {
	a.Logger.Info("Deploying FinalShell config...")
	fConfig := &FinalshellConfig{}

	path, err := fConfig.FindFinalshellConfigPaths()
	if err != nil {
		fallbackPath, fallbackErr := fallbackAccountPath("finalshell")
		if fallbackErr != nil {
			a.Logger.Error("Error finding FinalShell config path:", err)
			return fmt.Errorf("error finding FinalShell config path: %v", err)
		}
		path = fallbackPath
		a.Logger.Warnf("FinalShell path not found, use default software config directory: %s", path)
	}

	if err := fConfig.generateConfig(cfg.Username, cfg.Password, cfg.Host, cfg.Port, path); err != nil {
		a.Logger.Error("Error generating FinalShell config:", err)
		return fmt.Errorf("error generating FinalShell config: %v", err)
	}

	a.Logger.Infof("FinalShell configuration file path: %s", path)
	a.Logger.Info("FinalShell config deployed successfully.")
	return nil
}

func (a *AccountDeployer) DeployVPNConfig(remoteIP string, port int, path string) error {
	a.Logger.Info("Deploying OpenVPN config...")
	vpnConfig := &VPNConfig{RemoteIP: remoteIP}

	openVPNPath, err := vpnConfig.FindOpenVPNConfigPaths()
	if err != nil {
		fallbackPath, fallbackErr := fallbackAccountPath("openvpn")
		if fallbackErr != nil {
			a.Logger.Error("Error finding OpenVPN config path:", err)
			return fmt.Errorf("error finding OpenVPN config path: %v", err)
		}
		openVPNPath = fallbackPath
		a.Logger.Warnf("OpenVPN path not found, use default software config directory: %s", openVPNPath)
	}

	configFilePath, err := vpnConfig.createFakeConfig(openVPNPath)
	if err != nil {
		a.Logger.Error("Error generating VPN config:", err)
		return fmt.Errorf("error generating VPN config: %v", err)
	}

	a.Logger.Infof("OpenVPN config file path: %s", configFilePath)
	a.Logger.Infof("OpenVPN config deployed successfully.")
	return nil
}

func generateFinalshellRandomID(length int) string {
	source := rand.NewSource(time.Now().UnixNano())
	random := rand.New(source)

	const letterBytes = "abcdefghijklmnopqrstuvwxyz1234567890"
	var sb strings.Builder
	sb.Grow(length)

	for i := 0; i < length; i++ {
		sb.WriteByte(letterBytes[random.Intn(len(letterBytes))])
	}
	return sb.String()
}

func getUniqueFilePath(basePath string) string {
	ext := filepath.Ext(basePath)
	name := basePath
	if ext != "" {
		name = strings.TrimSuffix(basePath, ext)
	}
	counter := 1
	filePath := basePath

	for {
		if _, err := os.Stat(filePath); os.IsNotExist(err) {
			break
		}
		filePath = fmt.Sprintf("%s_%d%s", name, counter, ext)
		counter++
	}

	return filePath
}
