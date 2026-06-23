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
	a.Logger.Info("Start automatic deployment of Xshell configuration files...")
	xConfig := &XshellConfig{}

	path, err := xConfig.FindXshellConfigPaths()
	if err != nil {
		fallbackPath, fallbackErr := fallbackAccountPath("xshell")
		if fallbackErr != nil {
			a.Logger.Error("error finding Xshell config path:", err)
			return fmt.Errorf("error finding Xshell config path: %v", err)
		}
		path = fallbackPath
		a.Logger.Warnf("Xshell path not found, use default software config directory: %s", path)
	}

	// Xshell works best when a Sessions directory already contains a template .xsh file.
	if !xConfig.hasXshFile(path) {
		fallbackPath, fallbackErr := fallbackAccountPath("xshell")
		if fallbackErr != nil {
			a.Logger.Error("no .xsh files found in the specified path:", path)
			return fmt.Errorf("no .xsh files found in the specified path: %s", path)
		}
		path = fallbackPath
		a.Logger.Warnf("No Xshell template session found, use default software config directory: %s", path)
	}

	if err := xConfig.generateXshellConfig(cfg.Username, cfg.Host, cfg.Port, cfg.Password, path); err != nil {
		a.Logger.Error("error generating Xshell config:", err)
		return fmt.Errorf("error generating Xshell config: %v", err)
	}

	a.Logger.Infof("Xshell configuration file path: %s", path)
	a.Logger.Infof("Xshell config file deployed successfully.")
	return nil
}

func (a *AccountDeployer) DeployFinalshellConfig(cfg models.ShellCfg) error {
	a.Logger.Info("Start automatic deployment of FinalShell configuration files...")
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
	a.Logger.Infof("FinalShell config file deployed successfully.")
	return nil
}

func (a *AccountDeployer) DeployVPNConfig(remoteIP string, port int, path string) error {
	a.Logger.Info("Start automatic deployment of OpenVPN configuration files...")
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
	a.Logger.Infof("OpenVPN config file deployed successfully.")
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
