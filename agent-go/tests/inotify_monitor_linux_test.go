package tests

import (
	"fmt"
	"log"
	"syscall" // 替换为你的包路径
	"testing"
	"unsafe"
)

func TestInotifyMonitor(t *testing.T) {
	test2()
	// var err error

	// // 初始化 InotifyMonitor
	// fd, err := syscall.InotifyInit()
	// path := "/home/cly/test"
	// // 使用inotify添加监控
	// wd, err := syscall.InotifyAddWatch(fd, path, syscall.IN_OPEN|syscall.IN_CREATE|syscall.IN_DELETE|syscall.IN_MODIFY|syscall.IN_ATTRIB|syscall.IN_MOVE)
	// defer syscall.InotifyRmWatch(fd, uint32(wd))

	// if err != nil {
	// 	// log.Printf("添加监控路径失败: %s, 错误: %v", "/home/cly/test", err)
	// 	t.Fatalf("添加监控路径失败: %v", err)
	// 	return
	// }
	// fmt.Println("正在监控当前目录中的文件变化...")
	// buf := make([]byte, 4096)
	// for {
	// 	// 阻塞读取 inotify 事件
	// 	n, err := syscall.Read(fd, buf)
	// 	if err != nil {
	// 		log.Fatal("读取 inotify 事件时出错:", err)
	// 	}

	// 	// 解析事件
	// 	var offset int
	// 	for offset < n {
	// 		event := (*syscall.InotifyEvent)(unsafe.Pointer(&buf[offset]))
	// 		offset += syscall.SizeofInotifyEvent

	// 		// 读取文件名
	// 		var name string
	// 		if event.Len > 0 {
	// 			name = string(buf[offset : offset+int(event.Len)-1])
	// 			offset += int(event.Len)
	// 		}

	// 		// 输出事件信息
	// 		if event.Mask&syscall.IN_CREATE == syscall.IN_CREATE {
	// 			fmt.Printf("文件创建: %s\n", name)
	// 		}
	// 		if event.Mask&syscall.IN_MODIFY == syscall.IN_MODIFY {
	// 			fmt.Printf("文件修改: %s\n", name)
	// 		}
	// 		if event.Mask&syscall.IN_DELETE == syscall.IN_DELETE {
	// 			fmt.Printf("文件删除: %s\n", name)
	// 		}
	// 	}
	// }
}

func test2() {
	// 初始化 inotify
	fd, err := syscall.InotifyInit()
	if err != nil {
		log.Fatal("无法初始化 inotify:", err)
	}
	defer syscall.Close(fd)

	// 监控当前目录的创建、删除和修改事件
	// wd, err := syscall.InotifyAddWatch(fd, "/home/cly/test", syscall.IN_CREATE|syscall.IN_DELETE|syscall.IN_MODIFY)
	wd, err := syscall.InotifyAddWatch(fd, "/home/cly/test", syscall.IN_ALL_EVENTS)
	if err != nil {
		log.Fatal("无法添加监控路径:", err)
	}
	defer syscall.InotifyRmWatch(fd, uint32(wd))

	fmt.Println("正在监控当前目录中的文件变化...")

	// 分配缓冲区来读取事件
	buf := make([]byte, 4096)

	for {
		// 阻塞读取 inotify 事件
		n, err := syscall.Read(fd, buf)
		if err != nil {
			log.Fatal("读取 inotify 事件时出错:", err)
		}

		// 解析事件
		var offset int
		for offset < n {
			event := (*syscall.InotifyEvent)(unsafe.Pointer(&buf[offset]))
			offset += syscall.SizeofInotifyEvent

			// 读取文件名
			var name string
			if event.Len > 0 {
				name = string(buf[offset : offset+int(event.Len)-1])
				offset += int(event.Len)
			}

			// 输出事件信息
			if event.Mask&syscall.IN_CREATE == syscall.IN_CREATE {
				fmt.Printf("文件创建: %s\n", name)
			}
			if event.Mask&syscall.IN_MODIFY == syscall.IN_MODIFY {
				fmt.Printf("文件修改: %s\n", name)
			}
			if event.Mask&syscall.IN_DELETE == syscall.IN_DELETE {
				fmt.Printf("文件删除: %s\n", name)
			}
		}
	}
}

func test3() {
	// 初始化 inotify
	fd, err := syscall.InotifyInit()
	if err != nil {
		log.Fatal("无法初始化 inotify:", err)
	}
	defer syscall.Close(fd)

	// 监控指定路径中的所有事件
	wd, err := syscall.InotifyAddWatch(fd, "/home/cly/test", syscall.IN_ALL_EVENTS)
	if err != nil {
		log.Fatal("无法添加监控路径:", err)
	}
	defer syscall.InotifyRmWatch(fd, uint32(wd))

	fmt.Println("正在监控 /home/cly/test 路径中的文件变化...")

	// 分配缓冲区来读取事件
	buf := make([]byte, 4096)

	for {
		// 阻塞读取 inotify 事件
		n, err := syscall.Read(fd, buf)
		if err != nil {
			log.Fatal("读取 inotify 事件时出错:", err)
		}

		// 解析事件
		var offset int
		for offset < n {
			event := (*syscall.InotifyEvent)(unsafe.Pointer(&buf[offset]))
			offset += syscall.SizeofInotifyEvent

			// 读取文件名
			var name string
			if event.Len > 0 {
				name = string(buf[offset : offset+int(event.Len)-1])
				offset += int(event.Len)
			}

			// 输出所有事件信息
			fmt.Printf("事件掩码: %d, 文件名: %s\n", event.Mask, name)

			// 打印具体事件类型
			if event.Mask&syscall.IN_CREATE == syscall.IN_CREATE {
				fmt.Printf("文件创建: %s\n", name)
			}
			if event.Mask&syscall.IN_MODIFY == syscall.IN_MODIFY {
				fmt.Printf("文件修改: %s\n", name)
			}
			if event.Mask&syscall.IN_DELETE == syscall.IN_DELETE {
				fmt.Printf("文件删除: %s\n", name)
			}
			if event.Mask&syscall.IN_OPEN == syscall.IN_OPEN {
				fmt.Printf("文件打开: %s\n", name)
			}
			if event.Mask&syscall.IN_CLOSE_WRITE == syscall.IN_CLOSE_WRITE {
				fmt.Printf("文件关闭后写入: %s\n", name)
			}
			if event.Mask&syscall.IN_CLOSE_NOWRITE == syscall.IN_CLOSE_NOWRITE {
				fmt.Printf("文件关闭未写入: %s\n", name)
			}
			if event.Mask&syscall.IN_ACCESS == syscall.IN_ACCESS {
				fmt.Printf("文件被访问: %s\n", name)
			}
			if event.Mask&syscall.IN_ATTRIB == syscall.IN_ATTRIB {
				fmt.Printf("文件属性改变: %s\n", name)
			}
			if event.Mask&syscall.IN_MOVE_SELF == syscall.IN_MOVE_SELF {
				fmt.Printf("被监控的文件自身被移动: %s\n", name)
			}
			if event.Mask&syscall.IN_MOVED_FROM == syscall.IN_MOVED_FROM {
				fmt.Printf("文件被移出: %s\n", name)
			}
			if event.Mask&syscall.IN_MOVED_TO == syscall.IN_MOVED_TO {
				fmt.Printf("文件被移动到此处: %s\n", name)
			}
			if event.Mask&syscall.IN_DELETE_SELF == syscall.IN_DELETE_SELF {
				fmt.Printf("被监控的文件自身被删除: %s\n", name)
			}
			if event.Mask&syscall.IN_UNMOUNT == syscall.IN_UNMOUNT {
				fmt.Printf("文件所在文件系统被卸载: %s\n", name)
			}
		}
	}
}
