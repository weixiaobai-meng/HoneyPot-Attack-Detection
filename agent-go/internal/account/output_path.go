package account

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
)

func ensureDir(path string) (string, error) {
	if strings.TrimSpace(path) == "" {
		return "", fmt.Errorf("empty directory path")
	}

	absPath, err := filepath.Abs(path)
	if err != nil {
		return "", err
	}

	if err := os.MkdirAll(absPath, 0755); err != nil {
		return "", err
	}

	return absPath, nil
}

func fallbackAccountPath(kind string) (string, error) {
	root := strings.TrimSpace(os.Getenv("SYSTEMWIRE_ACCOUNT_OUTPUT_DIR"))
	if root == "" {
		defaultPaths := defaultAccountConfigPaths(kind)
		for _, path := range defaultPaths {
			if strings.TrimSpace(path) == "" {
				continue
			}
			if info, err := os.Stat(path); err == nil && info.IsDir() {
				return ensureDir(path)
			}
		}
		for _, path := range defaultPaths {
			if strings.TrimSpace(path) == "" {
				continue
			}
			if ensuredPath, err := ensureDir(path); err == nil {
				return ensuredPath, nil
			}
		}
		return "", fmt.Errorf("no writable default config directory found for %s", kind)
	}

	return ensureDir(filepath.Join(root, kind))
}

func defaultAccountConfigPaths(kind string) []string {
	kind = strings.ToLower(strings.TrimSpace(kind))
	home := os.Getenv("USERPROFILE")
	if home == "" {
		home = os.Getenv("HOME")
	}

	if runtime.GOOS == "windows" {
		documents := filepath.Join(home, "Documents")
		programFiles := os.Getenv("PROGRAMFILES")
		programFilesX86 := os.Getenv("ProgramFiles(x86)")
		appData := os.Getenv("APPDATA")
		localAppData := os.Getenv("LOCALAPPDATA")

		switch kind {
		case "xshell":
			return []string{
				filepath.Join(documents, "NetSarang Computer", "9", "Xshell", "Sessions"),
				filepath.Join(documents, "NetSarang Computer", "8", "Xshell", "Sessions"),
				filepath.Join(documents, "NetSarang Computer", "7", "Xshell", "Sessions"),
				filepath.Join(documents, "NetSarang Computer", "Xshell", "Sessions"),
			}
		case "finalshell":
			return []string{
				filepath.Join(home, ".finalshell", "conn"),
				filepath.Join(localAppData, "finalshell", "conn"),
				filepath.Join(appData, "finalshell", "conn"),
				filepath.Join(documents, "FinalShell", "conn"),
				filepath.Join(programFiles, "FinalShell", "conn"),
				filepath.Join(programFilesX86, "FinalShell", "conn"),
				`D:\finalshell\conn`,
				`D:\FinalShell\conn`,
			}
		case "openvpn":
			return []string{
				filepath.Join(home, "OpenVPN", "config"),
				filepath.Join(home, "OpenVPN", "config-auto"),
				filepath.Join(programFiles, "OpenVPN", "config"),
				filepath.Join(programFilesX86, "OpenVPN", "config"),
				`C:\OpenVPN\config`,
			}
		}
	}

	switch kind {
	case "finalshell":
		return []string{
			filepath.Join(home, ".finalshell", "conn"),
			filepath.Join(home, ".config", "finalshell", "conn"),
		}
	case "openvpn":
		return []string{
			filepath.Join(home, ".config", "openvpn"),
			filepath.Join(home, ".openvpn"),
			"/etc/openvpn/client",
			"/etc/openvpn",
		}
	}
	return nil
}
