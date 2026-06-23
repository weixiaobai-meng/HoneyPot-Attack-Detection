package agent

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"systemwire/agent/internal/config"
	"systemwire/agent/internal/models"
	pb "systemwire/agent/proto"
	"time"
)

func (a *Agent) handlerAddPathCmd(cmd *pb.Cmd) error {
	paths := splitCSVPaths(cmd.Data)
	if len(paths) == 0 {
		return errors.New("no monitor paths provided")
	}
	if err := a.monitor.AddPaths(paths); err != nil {
		return err
	}
	return config.SaveMonitorPath("config/paths.list", a.monitor.GetPath())
}

func (a *Agent) handlerDelPathCmd(cmd *pb.Cmd) error {
	paths := splitCSVPaths(cmd.Data)
	if len(paths) == 0 {
		return errors.New("no monitor paths provided")
	}
	return a.monitor.RemovePath(paths)
}

func splitCSVPaths(value string) []string {
	parts := strings.Split(value, ",")
	paths := make([]string, 0, len(parts))
	for _, part := range parts {
		path := strings.TrimSpace(part)
		if path != "" {
			paths = append(paths, path)
		}
	}
	return paths
}

func (a *Agent) handlerAddAccount(cmd *pb.Cmd) error {
	commandData := strings.Split(cmd.Data, ":")
	if len(commandData) == 0 || strings.TrimSpace(commandData[0]) == "" {
		return errors.New("missing account deployment type")
	}

	accountType := strings.ToLower(strings.TrimSpace(commandData[0]))
	if accountType == "auto" {
		return errors.New("automatic account generation is not supported in the current agent, please submit a concrete account profile")
	}
	if len(commandData) < 3 {
		return errors.New("missing parameters, expected [accountType]:[host]:[port]:<username>:<password>")
	}

	switch accountType {
	case "ssh":
		return errors.New("ssh plain credential deployment is not implemented, please use xshell, finalshell or openvpn")
	case "xshell":
		if len(commandData) < 5 {
			return fmt.Errorf("missing parameters: %v, expected [xshell]:[host]:[port]:[username]:[password]", cmd.Data)
		}
		port, err := parseTCPPort(commandData[2])
		if err != nil {
			return err
		}
		cfg := &models.ShellCfg{
			Host:     commandData[1],
			Port:     port,
			Username: commandData[3],
			Password: commandData[4],
		}
		return a.accountDeployer.DeployXshellConfig(*cfg)
	case "finall", "finalshell":
		if len(commandData) < 5 {
			return fmt.Errorf("missing parameters: %v, expected [finalshell]:[host]:[port]:[username]:[password]", cmd.Data)
		}
		port, err := parseTCPPort(commandData[2])
		if err != nil {
			return err
		}
		cfg := &models.ShellCfg{
			Host:     commandData[1],
			Port:     port,
			Username: commandData[3],
			Password: commandData[4],
		}
		return a.accountDeployer.DeployFinalshellConfig(*cfg)
	case "openvpn":
		port, err := parseTCPPort(commandData[2])
		if err != nil {
			return err
		}
		return a.accountDeployer.DeployVPNConfig(commandData[1], port, "")
	default:
		return fmt.Errorf("unknown account type: %v", accountType)
	}
}

func parseTCPPort(value string) (int, error) {
	portText := strings.TrimSpace(value)
	port, err := strconv.Atoi(portText)
	if err != nil {
		return 0, fmt.Errorf("invalid port: %v", value)
	}
	if port < 1 || port > 65535 {
		return 0, fmt.Errorf("invalid port: %d, expected 1-65535", port)
	}
	return port, nil
}

func (a *Agent) handlerDeployFileHoneypot(cmd *pb.Cmd) error {
	type FileItem struct {
		FileID      int    `json:"file_id"`
		FileName    string `json:"filename"`
		DownloadURL string `json:"download_url"`
	}

	type FileHoneypotCmd struct {
		FileID      int        `json:"file_id"`
		FileName    string     `json:"filename"`
		DownloadURL string     `json:"download_url"`
		Files       []FileItem `json:"files"`
		DeployPaths []string   `json:"deploy_paths"`
		Monitor     bool       `json:"monitor"`
	}

	var fc FileHoneypotCmd
	if err := json.Unmarshal([]byte(cmd.Data), &fc); err != nil {
		return fmt.Errorf("parse file honeypot deployment command failed: %v", err)
	}

	if len(fc.Files) == 0 {
		if strings.TrimSpace(fc.DownloadURL) == "" {
			return fmt.Errorf("download_url is required")
		}
		fc.Files = []FileItem{{
			FileID:      fc.FileID,
			FileName:    fc.FileName,
			DownloadURL: fc.DownloadURL,
		}}
	}

	deployPaths := normalizeUniquePaths(fc.DeployPaths)
	if len(deployPaths) == 0 {
		return fmt.Errorf("deploy_paths is required")
	}

	a.Logger.Infof("start deploying file honeypots: files=%d paths=%d", len(fc.Files), len(deployPaths))
	client := &http.Client{Timeout: 30 * time.Second}
	deployedPaths := []string{}

	for _, item := range fc.Files {
		data, err := downloadWithRetry(client, strings.TrimSpace(item.DownloadURL), 3)
		if err != nil {
			return fmt.Errorf("download file honeypot failed file_id=%d: %v", item.FileID, err)
		}

		filename := sanitizeFilename(strings.TrimSpace(item.FileName))
		if filename == "" {
			filename = fmt.Sprintf("honeypot_file_%d", item.FileID)
		}

		for _, deployPath := range deployPaths {
			if err := os.MkdirAll(deployPath, 0755); err != nil {
				a.Logger.Errorf("create deploy directory failed %s: %v", deployPath, err)
				continue
			}

			filePath := filepath.Join(deployPath, filename)
			if err := os.WriteFile(filePath, data, 0644); err != nil {
				a.Logger.Errorf("write file honeypot failed %s: %v", filePath, err)
				continue
			}

			a.Logger.Infof("file honeypot deployed: %s", filePath)
			deployedPaths = append(deployedPaths, filePath)
		}
	}

	if len(deployedPaths) == 0 {
		return fmt.Errorf("file honeypot deployment failed for all target paths")
	}

	if fc.Monitor {
		monitorPaths := uniqueDirectories(deployedPaths)
		if err := a.monitor.AddPaths(monitorPaths); err != nil {
			a.Logger.Errorf("add monitor paths failed: %v", err)
		} else {
			if err := config.SaveMonitorPath("config/paths.list", a.monitor.GetPath()); err != nil {
				a.Logger.Errorf("save monitor paths failed: %v", err)
			}
			a.Logger.Infof("monitor paths added: %v", monitorPaths)
		}
	}

	return nil
}

func (a *Agent) handlerDeployParasitic(cmd *pb.Cmd) error {
	type ParasiticCmd struct {
		TargetDir  string `json:"target_dir"`
		JSUrl      string `json:"js_url"`
		JSContent  string `json:"js_content"`
		InjectMode string `json:"inject_mode"`
		Backup     bool   `json:"backup"`
	}

	var pc ParasiticCmd
	if err := json.Unmarshal([]byte(cmd.Data), &pc); err != nil {
		return fmt.Errorf("parse parasitic deployment command failed: %v", err)
	}

	pc.TargetDir = strings.TrimSpace(pc.TargetDir)
	pc.JSUrl = strings.TrimSpace(pc.JSUrl)
	pc.InjectMode = strings.TrimSpace(pc.InjectMode)
	if pc.TargetDir == "" {
		return fmt.Errorf("target_dir is required")
	}
	pc.TargetDir = normalizeParasiticTargetDir(pc.TargetDir)
	if pc.InjectMode == "" {
		pc.InjectMode = "inline"
	}

	jsContent, err := loadParasiticJS(pc.JSUrl, pc.JSContent)
	if err != nil {
		return err
	}

	files, err := os.ReadDir(pc.TargetDir)
	if err != nil {
		return fmt.Errorf("read target_dir failed: %v", err)
	}

	htmlCount := 0
	injectedCount := 0
	alreadyInjectedCount := 0
	failedCount := 0
	for _, file := range files {
		if file.IsDir() || !isHTMLFile(file.Name()) {
			continue
		}
		htmlCount++

		filePath := filepath.Join(pc.TargetDir, file.Name())
		htmlContent, err := os.ReadFile(filePath)
		if err != nil {
			a.Logger.Errorf("read html file failed %s: %v", filePath, err)
			failedCount++
			continue
		}
		if pc.Backup {
			backupPath := filePath + ".bak"
			if err := os.WriteFile(backupPath, htmlContent, 0644); err != nil {
				a.Logger.Errorf("backup html file failed %s: %v", filePath, err)
			}
		}

		injectCode := buildParasiticInjectCode(pc.InjectMode, pc.JSUrl, jsContent)
		htmlStr := string(htmlContent)
		if strings.Contains(htmlStr, parasiticInjectMarker) {
			nextHTML, replaced := replaceExistingParasiticInjectCode(htmlStr, injectCode)
			if !replaced {
				a.Logger.Errorf("replace old parasitic block failed: %s", filePath)
				failedCount++
				continue
			}
			htmlStr = nextHTML
			alreadyInjectedCount++
		} else if strings.Contains(htmlStr, "</body>") {
			htmlStr = strings.Replace(htmlStr, "</body>", injectCode+"\n</body>", 1)
		} else if strings.Contains(htmlStr, "</BODY>") {
			htmlStr = strings.Replace(htmlStr, "</BODY>", injectCode+"\n</BODY>", 1)
		} else {
			htmlStr += "\n" + injectCode
		}

		if err := os.WriteFile(filePath, []byte(htmlStr), 0644); err != nil {
			a.Logger.Errorf("write injected html failed %s: %v", filePath, err)
			failedCount++
			continue
		}
		if alreadyInjectedCount > 0 && strings.Contains(string(htmlContent), parasiticInjectMarker) {
			a.Logger.Infof("parasitic honeypot updated: %s", filePath)
		} else {
			a.Logger.Infof("parasitic honeypot injected: %s", filePath)
		}
		injectedCount++
	}

	if htmlCount == 0 {
		return fmt.Errorf("no html or htm files found in target_dir")
	}
	if injectedCount == 0 && alreadyInjectedCount > 0 && failedCount == 0 {
		a.Logger.Infof("parasitic deployment completed, %d html files were already injected", alreadyInjectedCount)
		return nil
	}
	if injectedCount == 0 {
		return fmt.Errorf("no html files were injected in target_dir, html=%d already_injected=%d failed=%d", htmlCount, alreadyInjectedCount, failedCount)
	}
	a.Logger.Infof("parasitic deployment completed, injected %d files", injectedCount)
	return nil
}

func (a *Agent) handlerSendFile(cmd *pb.Cmd) error {
	type FileCmd struct {
		FileID      int    `json:"file_id"`
		FileName    string `json:"filename"`
		ServerPath  string `json:"server_path"`
		RemotePath  string `json:"remote_path"`
		DownloadURL string `json:"download_url"`
	}

	var fc FileCmd
	if err := json.Unmarshal([]byte(cmd.Data), &fc); err != nil {
		return fmt.Errorf("parse send_file command failed: %v", err)
	}

	filename := sanitizeFilename(strings.TrimSpace(fc.FileName))
	if filename == "" {
		filename = "downloaded_file"
	}

	var data []byte
	var err error
	if strings.TrimSpace(fc.DownloadURL) != "" {
		client := &http.Client{Timeout: 30 * time.Second}
		data, err = downloadWithRetry(client, strings.TrimSpace(fc.DownloadURL), 3)
		if err != nil {
			return fmt.Errorf("download file failed: %v", err)
		}
		if filename == "downloaded_file" {
			filename = filenameFromURL(fc.DownloadURL, filename)
		}
	} else {
		if strings.TrimSpace(fc.ServerPath) == "" {
			return fmt.Errorf("server_path or download_url is required")
		}
		data, err = os.ReadFile(fc.ServerPath)
		if err != nil {
			return fmt.Errorf("read server_path failed: %v", err)
		}
		if filename == "downloaded_file" {
			filename = sanitizeFilename(filepath.Base(fc.ServerPath))
		}
	}

	remotePath := strings.TrimSpace(fc.RemotePath)
	if remotePath == "" {
		return fmt.Errorf("remote_path is required")
	}

	if info, err := os.Stat(remotePath); err == nil && info.IsDir() {
		remotePath = filepath.Join(remotePath, filename)
	} else if os.IsNotExist(err) {
		if err := os.MkdirAll(filepath.Dir(remotePath), 0755); err != nil {
			return fmt.Errorf("create remote directory failed: %v", err)
		}
	}

	remotePath = filepath.Clean(remotePath)
	if err := os.WriteFile(remotePath, data, 0644); err != nil {
		return fmt.Errorf("write remote file failed: %v", err)
	}

	a.Logger.Infof("file sent successfully: %s", remotePath)
	return nil
}

func loadParasiticJS(jsURL, jsContent string) ([]byte, error) {
	if jsContent != "" {
		return []byte(jsContent), nil
	}
	if jsURL == "" {
		return nil, fmt.Errorf("provide js_url or js_content")
	}
	if !strings.HasPrefix(strings.ToLower(jsURL), "http://") && !strings.HasPrefix(strings.ToLower(jsURL), "https://") {
		return os.ReadFile(filepath.Clean(jsURL))
	}

	client := &http.Client{Timeout: 30 * time.Second}
	return downloadWithRetry(client, jsURL, 3)
}

func buildParasiticInjectCode(injectMode, jsURL string, jsContent []byte) string {
	if injectMode == "script_tag" && jsURL != "" {
		return fmt.Sprintf("%s\n<script src=\"%s\" defer></script>", parasiticInjectMarker, jsURL)
	}
	return fmt.Sprintf("%s\n<script>\n%s\n</script>", parasiticInjectMarker, string(jsContent))
}

const parasiticInjectMarker = "<!-- honeypot-parasitic-marker -->"

func replaceExistingParasiticInjectCode(htmlStr, injectCode string) (string, bool) {
	markerIndex := strings.Index(htmlStr, parasiticInjectMarker)
	if markerIndex < 0 {
		return htmlStr, false
	}

	afterMarker := htmlStr[markerIndex+len(parasiticInjectMarker):]
	lowerAfterMarker := strings.ToLower(afterMarker)
	scriptIndex := strings.Index(lowerAfterMarker, "<script")
	if scriptIndex < 0 {
		return htmlStr, false
	}

	afterScript := afterMarker[scriptIndex:]
	lowerAfterScript := strings.ToLower(afterScript)
	openEndIndex := strings.Index(lowerAfterScript, ">")
	if openEndIndex < 0 {
		return htmlStr, false
	}

	openingTag := strings.TrimSpace(afterScript[:openEndIndex+1])
	var relativeEnd int
	if strings.HasSuffix(openingTag, "/>") {
		relativeEnd = scriptIndex + openEndIndex + 1
	} else {
		closeIndex := strings.Index(lowerAfterScript[openEndIndex+1:], "</script>")
		if closeIndex < 0 {
			return htmlStr, false
		}
		relativeEnd = scriptIndex + openEndIndex + 1 + closeIndex + len("</script>")
	}

	endIndex := markerIndex + len(parasiticInjectMarker) + relativeEnd
	return htmlStr[:markerIndex] + injectCode + htmlStr[endIndex:], true
}

func normalizeParasiticTargetDir(target string) string {
	target = strings.TrimSpace(target)
	if strings.HasPrefix(strings.ToLower(target), "file://") {
		if parsed, err := url.Parse(target); err == nil {
			if parsed.Path != "" {
				target = parsed.Path
				if len(target) >= 3 && target[0] == '/' && target[2] == ':' {
					target = target[1:]
				}
				if decoded, err := url.PathUnescape(target); err == nil {
					target = decoded
				}
			}
		}
	}
	target = filepath.FromSlash(target)
	if isHTMLFile(filepath.Base(target)) {
		return filepath.Dir(target)
	}
	return target
}

func isHTMLFile(name string) bool {
	lower := strings.ToLower(name)
	return strings.HasSuffix(lower, ".html") || strings.HasSuffix(lower, ".htm")
}

func normalizeUniquePaths(paths []string) []string {
	result := []string{}
	seen := map[string]bool{}
	for _, path := range paths {
		path = strings.TrimSpace(path)
		if path == "" {
			continue
		}
		cleaned := filepath.Clean(path)
		if !seen[cleaned] {
			result = append(result, cleaned)
			seen[cleaned] = true
		}
	}
	return result
}

func uniqueDirectories(paths []string) []string {
	result := []string{}
	seen := map[string]bool{}
	for _, path := range paths {
		dir := filepath.Dir(path)
		if !seen[dir] {
			result = append(result, dir)
			seen[dir] = true
		}
	}
	return result
}

func downloadWithRetry(client *http.Client, downloadURL string, attempts int) ([]byte, error) {
	if strings.TrimSpace(downloadURL) == "" {
		return nil, fmt.Errorf("download_url is required")
	}

	var lastErr error
	for i := 0; i < attempts; i++ {
		resp, err := client.Get(downloadURL)
		if err != nil {
			lastErr = err
			time.Sleep(time.Second * time.Duration(i+1))
			continue
		}

		data, readErr := io.ReadAll(resp.Body)
		closeErr := resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			lastErr = fmt.Errorf("http status %d", resp.StatusCode)
			time.Sleep(time.Second * time.Duration(i+1))
			continue
		}
		if readErr != nil {
			lastErr = readErr
			continue
		}
		if closeErr != nil {
			lastErr = closeErr
			continue
		}
		return data, nil
	}

	if lastErr == nil {
		lastErr = fmt.Errorf("download failed")
	}
	return nil, lastErr
}

func filenameFromURL(rawURL, fallback string) string {
	parsedURL, err := url.Parse(rawURL)
	if err != nil {
		return sanitizeFilename(fallback)
	}
	name := filepath.Base(parsedURL.Path)
	if name == "" || name == "/" || name == "." {
		if id := parsedURL.Query().Get("id"); id != "" {
			name = "file_" + id
		} else {
			name = fallback
		}
	}
	return sanitizeFilename(name)
}

func sanitizeFilename(filename string) string {
	filename = strings.TrimSpace(filename)
	unsafeChars := []string{"<", ">", ":", "\"", "\\", "/", "|", "?", "*"}
	for _, char := range unsafeChars {
		filename = strings.ReplaceAll(filename, char, "_")
	}

	if len(filename) > 255 {
		ext := filepath.Ext(filename)
		base := filename[:255-len(ext)]
		filename = base + ext
	}

	reservedNames := []string{"CON", "PRN", "AUX", "NUL", "COM1", "COM2", "COM3", "COM4", "COM5", "COM6", "COM7", "COM8", "COM9", "LPT1", "LPT2", "LPT3", "LPT4", "LPT5", "LPT6", "LPT7", "LPT8", "LPT9"}
	baseName := strings.ToUpper(strings.TrimSuffix(filename, filepath.Ext(filename)))
	for _, reserved := range reservedNames {
		if baseName == reserved {
			filename = "_" + filename
			break
		}
	}

	var result strings.Builder
	for _, r := range filename {
		if r >= 32 && r != 127 {
			result.WriteRune(r)
		} else {
			result.WriteRune('_')
		}
	}
	return result.String()
}
