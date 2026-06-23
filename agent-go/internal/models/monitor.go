package models

import (
	"encoding/json"
	"fmt"
	pb "systemwire/agent/proto"
	"time"
)

// MonitorEvent 表示一个监控事件
type MonitorEvent struct {
	Id            string    `json:"id"`            // 事件id
	EventType     int       `json:"event_type_id"` // 事件类型id
	EventTypeName string    `json:"event_type"`    // 事件类型
	EventTime     time.Time `json:"event_time"`    // 事件发生时间
	User          string    `json:"user"`          // 系统用户
	Proc          string    `json:"proc"`          // 进程
	Pid           string    `json:"pid"`           // 进程ID
	PProc         string    `json:"pproc"`         // 父进程
	Args          string    `json:"args"`          // 参数
	Path          string    `json:"path"`          // 路径
	Data          string    `json:"data"`          // 其他数据
}

// 转换成json
func (event *MonitorEvent) GetEventPb() *pb.MonitorEvent {
	// 将指定字段打包成 JSON
	jsonDataMap := map[string]string{
		"user":  event.User,
		"proc":  event.Proc,
		"pid":   event.Pid,
		"pproc": event.PProc,
		"args":  event.Args,
	}
	// 序列化 JSON 数据
	jsonData, err := json.Marshal(jsonDataMap)
	if err != nil {
		// 如果序列化失败，记录日志或处理错误
		fmt.Printf("Failed to marshal jsonData: %v\n", err)
		jsonData = []byte("{}") // 设置为空 JSON
	}
	return &pb.MonitorEvent{
		Id:        event.Id,
		EventType: uint64(event.EventType),
		TimeStamp: uint64(event.EventTime.Unix()), // 时间戳
		Path:      event.Path,
		Data:      event.Data,
		JsonData:  string(jsonData),
	}
}

// AuditRecord 表示一组完整的审计记录
type AuditRecord struct {
	Time    time.Time                    // 记录时间
	Serial  string                       // 序列号
	Records map[string]map[string]string // 按类型存储，每个类型记录里有一些键值对
	RawData string                       // 完整的原始数据
}

// EventActionType 定义事件类型常量
const (
	_ = iota
	EventTypeUnknown
	EventTypeCreate
	EventTypeWrite
	EventTypeModify
	EventTypeDelete
	EventTypeAccess
	EventTypeOpen
	EventTypeAudit
	EventTypeRename
	EventTypeRead
	EventTypeCreateDir
	EventTypeDeleteDir
	EventTypeChmod
	EventTypeChown
	// 可以添加更多事件类型
)

func ActionStrToType(actionStr string) int {
	switch actionStr {
	case "openat", "open": // openat, open
		return EventTypeOpen
	case "read": // read
		return EventTypeRead
	case "write": // write
		return EventTypeWrite
	case "unlink", "unlinkat": // unlink, unlinkat
		return EventTypeDelete
	case "rename", "renameat": // rename, renameat
		return EventTypeRename
	case "mkdir": // mkdir
		return EventTypeCreateDir
	case "rmdir": // rmdir
		return EventTypeDeleteDir
	case "chmod", "fchmod": // chmod, fchmod
		return EventTypeChmod
	case "fchown": // fchown
		return EventTypeChown
	}
	return EventTypeUnknown
}
