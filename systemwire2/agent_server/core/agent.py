# agent 类
import queue

CmdBeat = 1                         # 心跳检测
CmdTypeStartMonitor = 2             # 启动监控
CmdTypeStopMonitor = 3              # 停止监控
CmdTypeRestartMonitor = 4           # 重启监控
CmdTypeAddPath = 5                  # 添加监控路径
CmdTypeDelPath = 6                  # 删除监控路径

class Agent():
    client_id = None              
    ip = None 
    client_name = None       # 探针名
    hostname = None         # 系统/主机名
    ope_sys = None          # 操作系统类型
    status = "offline"           # 在线状态
    token = None
    register_time = None    # 注册时间
    last_beat_time = None   # 上次心跳时间
    command_queue = None    # 任务队列
    
    def __init__(self,json_data:dict):
        self.client_id = json_data["client_id"]                 # 唯一id
        self.ip = json_data.get("ip")       
        self.ope_sys = json_data.get("ope_sys")                 # 操作系统
        self.client_name = json_data.get("client_name")         # 探针名
        self.hostname = json_data.get("hostname")               # 主机名
        self.token = json_data.get("token")
        self.register_time = json_data.get("register_time")     # 注册时间
        self.last_beat_time = json_data.get("last_beat_time")   # 最近心跳时间
        self.command_queue = queue.Queue()                      # 任务队列
        
