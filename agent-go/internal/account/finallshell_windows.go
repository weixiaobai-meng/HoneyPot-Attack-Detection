//go:build windows
// +build windows

package account

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"text/template"
	"time"
)

// FinalShell 闁板秶鐤嗙紒鎾寸€担?
type FinalshellConfig struct {
	ID         string `json:"id"`
	Host       string `json:"host"`
	UserName   string `json:"user_name"`
	Password   string `json:"password"`
	CreateTime int64  `json:"create_time"`
	ModfyTime  int64  `json:"modified_time"`
	Port       int    `json:"port"`
}

// 閻㈢喐鍨?FinalShell 闁板秶鐤?
func (f *FinalshellConfig) generateConfig(username string, password string, host string, port int, path string) error {
	// 鐠佸墽鐤嗙€涙顔?
	f.UserName = username
	f.Host = host
	f.Port = port
	f.ID = generateFinalshellRandomID(16) // 閻㈢喐鍨?6娴ｅ秹娈㈤張绡扗
	f.CreateTime = time.Now().UnixNano() / int64(time.Millisecond)
	if password == "" {
		f.Password = "P1sHUTIZXWxGQ72NBrtRJA==" // 閸ュ搫鐣剧€靛棛鐖?
	} else {
		f.Password = password
	}

	// 鐠囪褰囧Ο鈩冩緲閺傚洣娆㈤崘鍛啇
	templateFile := "config/templates/finalshell.txt" // 濡剝婢橀弬鍥︽閺€鎯ф躬 templates 閺傚洣娆㈡径閫涜厬
	templateData, err := os.ReadFile(templateFile)
	if err != nil {
		return fmt.Errorf("error reading template file %s: %v", templateFile, err)
	}

	// 娴ｈ法鏁ら弬鍥ㄦ拱濡剝婢橀惃鍕敶鐎瑰湱鏁撻幋鎰板帳缂冾喗鏋冩禒?
	// 閸掓稑缂撻弬鍥︽鐠侯垰绶?
	filePath := filepath.Join(path, f.ID+"_finalshell_config.json")
	filePath = getUniqueFilePath(filePath)

	// 閹垫挸绱戦弬鍥︽鏉╂稖顢戦崘娆忓弳
	file, err := os.Create(filePath)
	if err != nil {
		return fmt.Errorf("error creating file %s: %v", filePath, err)
	}
	defer file.Close()

	// 娴ｈ法鏁ゅΟ鈩冩緲閺囨寧宕叉潻娑滎攽閸斻劍鈧礁锝為崗?
	// 鐏忓棗鐡у▓鍨禌閹广垹鍩屽Ο鈩冩緲娑擃厼鑻熼崘娆忓弳閺傚洣娆?
	tmpl, err := template.New("finalshellConfig").Parse(string(templateData))
	if err != nil {
		return fmt.Errorf("error parsing template: %v", err)
	}

	// 閹笛嗩攽濡剝婢橀弴鎸庡床楠炶泛鍟撻崗銉︽瀮娴?
	err = tmpl.Execute(file, f)
	if err != nil {
		return fmt.Errorf("error executing template: %v", err)
	}

	return nil
}

// 閺屻儲澹?FinalShell 闁板秶鐤嗛弬鍥︽鐠侯垰绶為敍鍫熻穿閸氬牊澹傞幓蹇旀煙濡楀牞绱?
func (f *FinalshellConfig) FindFinalshellConfigPaths() (string, error) {
	// 閺傛澘顤冩妯款吇鐠侯垰绶炲Λ鈧弻銉礄娴兼ê鍘涜箛顐︹偓鐔尖偓姘朵壕閿?
	if path, found := f.checkDefaultPaths(); found {
		return path, nil
	}

	// 閼惧嘲褰囨す鍗炲З閸ｃ劌鍨悰?
	drives, err := GetDriveList()
	if err != nil {
		return "", fmt.Errorf("error getting drive list: %v", err)
	}

	// 閺呴缚鍏橀幍顐ｅ伎閹貉冨煑
	const (
		timeout     = 20 * time.Second
		concurrency = 2
	)
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	resultChan := make(chan string, len(drives))
	sem := make(chan struct{}, concurrency)

	// 楠炴儼顢戦幍顐ｅ伎娴兼ê瀵?
	for _, drive := range drives {
		go func(d string) {
			sem <- struct{}{}
			defer func() { <-sem }()

			paths, err := f.findFinalShellConn(d)
			if err != nil {
				fmt.Printf("Scan %s error: %v\n", d, err)
				return
			}

			for _, path := range paths {
				if f.isDirectoryExists(path) {
					resultChan <- path
					return
				}
			}
		}(drive)
	}

	// 缂佹挻鐏夌粵澶婄窡
	select {
	case path := <-resultChan:
		fmt.Println("Found valid FinalShell config directory:", path)
		return path, nil
	case <-ctx.Done():
		return "", fmt.Errorf("閹殿偅寮跨搾鍛閿涘本婀幍鎯у煂閺堝鏅ョ捄顖氱窞")
	}
}

// 閹笛嗩攽 PowerShell 閸涙垝鎶ら弻銉﹀閸氼偅婀?FinalShell\conn 閻╊喖缍?
func (f *FinalshellConfig) findFinalShellConn(drive string) ([]string, error) {
	drive = normalizeDrive(drive)
	psCmd := fmt.Sprintf("[Console]::OutputEncoding = [System.Text.Encoding]::UTF8; Get-ChildItem -Path %s -Directory -ErrorAction SilentlyContinue -Recurse | Where-Object { $_.FullName -match 'FinalShell\\\\conn' } | Select-Object -ExpandProperty FullName", drive)
	cmd := exec.Command("powershell", "-Command", psCmd)
	var out bytes.Buffer
	var stderr bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &stderr

	err := cmd.Run()
	if err != nil {
		if stderr.Len() > 0 {
			return nil, fmt.Errorf("PowerShell 閹笛嗩攽闁挎瑨顕? %v\n%s", err, stderr.String())
		}
	}

	// 鐟欙絾鐎界紒鎾寸亯
	output := strings.TrimSpace(out.String())
	if output == "" {
		return nil, nil
	}
	return strings.FieldsFunc(output, func(r rune) bool {
		return r == '\r' || r == '\n'
	}), nil
}

// 濡偓閺屻儳娲拌ぐ鏇氳厬閺勵垰鎯侀張?.json 閺傚洣娆㈤敍鍦榠nalShell 閻ㄥ嫰鍘ょ純顔芥瀮娴犺埖鐗稿蹇ョ礆
func (f *FinalshellConfig) hasJsonFile(path string) bool {
	err := filepath.Walk(path, func(fpath string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if !info.IsDir() && strings.HasSuffix(info.Name(), ".json") {
			return fmt.Errorf("found .json file") // 鐠哄啿鍤弬鍥︽闁秴宸?
		}
		return nil
	})
	return err != nil // 婵″倹鐏夐幍鎯у煂 .json 閺傚洣娆㈤敍灞藉灟鏉╂柨娲?true
}

// 濡偓閺屻儵绮拋銈呯暔鐟佸懓鐭惧?
func (f *FinalshellConfig) checkDefaultPaths() (string, bool) {
	defaultPaths := []string{
		filepath.Join(os.Getenv("USERPROFILE"), "Documents", "FinalShell", "conn"),
		filepath.Join(os.Getenv("PROGRAMFILES"), "FinalShell", "conn"),
		filepath.Join(os.Getenv("ProgramFiles(x86)"), "FinalShell", "conn"),
		`D:\finalshell\conn`,
		`D:\FinalShell\conn`,
		`C:\FinalShell\conn`,
	}

	for _, path := range defaultPaths {
		if f.isDirectoryExists(path) {
			fmt.Printf("闁俺绻冩妯款吇鐠侯垰绶為幍鎯у煂闁板秶鐤嗛惄顔肩秿: %s\n", path)
			return path, true
		}
	}
	return "", false
}

// 濡偓閺屻儳绮扮€规俺鐭惧鍕Ц閸氾箑鐡ㄩ崷銊ヨ嫙娑撴梹妲告稉鈧稉顏嗘窗瑜?
func (f *FinalshellConfig) isDirectoryExists(path string) bool {
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
