package command

import (
	"bufio"
	"encoding/json"
	"fmt"
	"math/rand"
	"os"
	"path/filepath"
)

// CommandGenerator 类
type CommandGenerator struct {
	otherFakeCommands []string
	monitoredPath     []string
	randomLs          []string
	randomCat         []string
	scaleOfCommands   int
}

// NewCommandGenerator 创建一个新的 CommandGenerator 实例
func NewCommandGenerator(jsonFilename string, scaleOfCommands int, monitoredPath []string) (*CommandGenerator, error) {
	otherFakeCommands, err := loadSliceFromJSON(jsonFilename)
	if err != nil {
		return nil, err
	}

	randomLs := []string{"ls", "ls -l", "ls -la", "ls -lh"}
	randomCat := []string{"cat ", "less ", "stat ", "more "}

	return &CommandGenerator{
		otherFakeCommands: otherFakeCommands,
		monitoredPath:     monitoredPath,
		randomLs:          randomLs,
		randomCat:         randomCat,
		scaleOfCommands:   scaleOfCommands,
	}, nil
}

// 从 JSON 文件读取数据并赋值给切片
func loadSliceFromJSON(filename string) ([]string, error) {
	data, err := os.ReadFile(filename)
	if err != nil {
		return nil, fmt.Errorf("failed to read JSON file: %v", err)
	}

	var slice []string
	err = json.Unmarshal(data, &slice)
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal JSON data: %v", err)
	}

	return slice, nil
}

// 随机从切片中选择一个元素
func (cg *CommandGenerator) randomElement(slice []string) (string, error) {
	if len(slice) == 0 {
		return "", fmt.Errorf("slice is empty")
	}
	randomIndex := rand.Intn(len(slice))
	return slice[randomIndex], nil
}

// 生成指定范围内的随机整数
func (cg *CommandGenerator) randomIntInRange(min, max int) int {
	if min > max {
		panic("min 不能大于 max")
	}
	return rand.Intn(max-min+1) + min
}

// 列出指定目录中的所有文件（相对路径）
func (cg *CommandGenerator) listAllFiles(directory string) ([]string, error) {
	var allFiles []string
	err := filepath.Walk(directory, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if !info.IsDir() {
			relPath, err := filepath.Rel(directory, path)
			if err != nil {
				return err
			}
			allFiles = append(allFiles, relPath)
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return allFiles, nil
}

// 检查路径类型
func (cg *CommandGenerator) checkPath(path string) int {
	info, err := os.Stat(path)
	if os.IsNotExist(err) {
		fmt.Printf("error: %s 不是一个有效的文件或文件夹路径\n", path)
		return -1
	}
	if err != nil {
		fmt.Printf("error: 检查路径出错 %v\n", err)
		return -1
	}
	if info.IsDir() {
		return 1 // 是文件夹
	}
	return 0 // 是文件
}

// 将伪造的命令写入历史记录文件
func (cg *CommandGenerator) writeHistory(history []string) {
	historyFile := filepath.Join(os.Getenv("HOME"), ".bash_history")

	file, err := os.OpenFile(historyFile, os.O_APPEND|os.O_WRONLY|os.O_CREATE, 0644)
	if err != nil {
		fmt.Printf("Error opening history file: %v\n", err)
		return
	}
	defer file.Close()

	writer := bufio.NewWriter(file)
	for _, command := range history {
		_, err := writer.WriteString(command + "\n")
		if err != nil {
			fmt.Printf("Error writing fake commands: %v\n", err)
			return
		}
	}
	err = writer.Flush()
	if err != nil {
		fmt.Printf("Error flushing data to history file: %v\n", err)
		return
	}
	fmt.Println("Fake commands inserted successfully.")
}

// 生成伪造的命令
func (cg *CommandGenerator) GenerateCommands() error {
	var history []string
	count := cg.scaleOfCommands
	for count > 0 {
		scale := cg.randomIntInRange(5, cg.scaleOfCommands/5)
		for i := 0; i < scale; i++ {
			randomOtherCommand, _ := cg.randomElement(cg.otherFakeCommands)
			history = append(history, randomOtherCommand)
		}
		count = count - scale
		path, _ := cg.randomElement(cg.monitoredPath)
		if cg.checkPath(path) == 0 {
			trapCommand, _ := cg.randomElement(cg.randomCat)
			trapCommand = trapCommand + path
			history = append(history, trapCommand)
		} else if cg.checkPath(path) == 1 {
			allFiles, err := cg.listAllFiles(path)
			if err != nil {
				return fmt.Errorf("Error listing files: %v", err)
			}
			firstCommand := "cd " + path
			history = append(history, firstCommand)
			secondCommand, _ := cg.randomElement(cg.randomLs)
			history = append(history, secondCommand)
			thirdCommand, _ := cg.randomElement(cg.randomCat)
			randomFile, _ := cg.randomElement(allFiles)
			thirdCommand = thirdCommand + randomFile
			history = append(history, thirdCommand)
		}
	}
	cg.writeHistory(history)
	return nil
}

//func main() {
//	// 创建 CommandGenerator 实例
//	cg, err := NewCommandGenerator("json/otherFakeCommands.json", 100, []string{"/home/yiyi/股东信息.docx", "/home/yiyi/confidential"})
//	if err != nil {
//		log.Fatalf("Error creating CommandGenerator: %v\n", err)
//	}
//
//	// 生成伪造的命令
//	err = cg.GenerateCommands()
//	if err != nil {
//		log.Fatalf("Error generating commands: %v\n", err)
//	}
//}
