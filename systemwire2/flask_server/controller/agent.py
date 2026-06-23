import os
import requests
import json
import socket
import cmd
import netifaces
import time
import shutil
from tqdm import tqdm



# hp_address = "http://172.25.0.100:5001" #蜜点服务器地址
hp_address = "" #蜜点服务器地址
template_list = []
email = ""  # 告警接收邮箱


class Agent(cmd.Cmd):
    intro = "Welcome to the agent shell. Type help or ? to list commands.\n"
    prompt = ">>"
    def do_setConfig(self,arg):
        isQuit = False
        while not isQuit:
            address = input("请输入蜜点管理服务器ip:(输入q退出)")
            # 检查地址是否合法ip
            if not address: # 判断是否为空
                print("地址不能为空")
                continue
            elif address == "q":    # 判断是否退出
                return True
            elif not is_valid_ipv4_address(address):    # 判断是否合法ip
                print("ip不合法")
                continue
            else:
                global hp_address
                hp_address = "http://" + address + ":5001"
                isQuit = True # 退出循环
        """打印配置信息"""
        print("hp_address:" + hp_address)

    def do_getTemplate(self,arg): #根据格式获取所有模板
        """列出所有模板
        用法：listTemplate [格式]
        例如：listTemplate docx
        """
        global template_list
        with tqdm(total=100,desc="获取列表",leave=True,ncols=100) as pbar: # 添加进度条
            url_fileTemplate = hp_address + "/file/template"
            if not arg:
                arg = ""
            elif arg.lower not in ["docx","xlsx"]:
                print("格式错误")
                return False  
            time.sleep(0.3)
            pbar.update(10)
            data = {"fomat":arg}
            json_data = json.dumps(data)

            headers = {'Content-Type': 'application/json'}
            cookies = {"Authorization": "Key"}
            time.sleep(0.3)
            pbar.update(10)
            try:
                response = requests.post(url_fileTemplate,data=json_data,headers=headers,cookies=cookies,timeout=10)
                time.sleep(0.6)
                pbar.update(40)
            except Exception as e:
                pbar.write(f"请求模板失败:{str(e)}")
                return False
            if response.status_code != 200:
                pbar.write("请求模板失败")
                return False
            else:
                # print(response.json()["data"])
                template_list = response.json()["data"][:]
            pbar.update(40)
        print("模板文件列表：")
        for i in range(len(template_list)):
            print(str(i+1)+"."+template_list[i])

    def do_downloadFile(self,arg):
        """下载文件
        用法：downloadFile [文件序列号]
        例如：downloadFile 1
        """
        ### 检查参数
        if not arg:
            print("参数错误：请输入文件序列号，例如：downloadFile 1")
            return False

        ### 用户选择模板
        global template_list
        file_num = int(arg) - 1
        email = ""
        # print(template_list)
        file_name = template_list[file_num] #获取模板文件名
        format = file_name.split(".")[-1] #获取模板文件格式
        
        ### 根据文件模板创建文件蜜点
        with tqdm(total=100,desc="创建文件蜜点",leave=True,ncols=100) as pbar:
            url_createFile = hp_address + "/file/create"
            ip = socket.gethostbyname(socket.gethostname()) # 获取IP
            machine_name = os.popen('hostname').read().strip() # 获取机器名
            if os.name == "nt": sys = "Windows"   # 判断操作系统类型
            if os.name == "posix": sys = "Linux"
            if os.name == "mac": sys = "Mac"
            time.sleep(0.3)
            pbar.update(40)
            pdata = {
                    "honeypoint_name": "hp-用户机部署",
                    "format": format,
                    "email": email,
                    "message": ip + "-" + machine_name + "-" + sys + "-触发告警", #告警信息格式：ip+机器名+系统
                    "source":0,
                    "template_name": file_name,
                    "server":"external"

                }
            
            data = {
                "data": json.dumps(pdata)
            }
            # print(data)
            response = requests.post(url_createFile,data=data)
            if response.status_code != 200:
                pbar.write("创建文件蜜点失败")
                return False
            elif response.json()["code"] != 0:
                pbar.write(f"创建文件蜜点失败:{response.json()['message']}")
                time.sleep(0.3)
                return False
            file_id = response.json()["data"]["id"]
            pbar.write(str(file_id))
            pbar.update(60)

        ### 下载文件蜜点
        url_downloadFile = hp_address + "/file/download"
        params = {"id":file_id}
        response = requests.post(url_downloadFile,params=params)
        if response.status_code != 200:
            print("下载文件失败")
            return False
        # 接收文件
        file_size = int(response.headers.get('Content-Length', 0))
        progress_bar = tqdm(total=file_size,desc="文件下载", unit='B', unit_scale=True)
        with open(file_name, 'wb') as f:
            for data in response.iter_content(chunk_size=1024):
                f.write(data)
                progress_bar.update(len(data))
        progress_bar.close()
        print(file_name + " 下载成功")


        ### 获取文件蜜点部署路径
        url_filePath = hp_address + "/file/path_generate"
        data = {
            "honeyfile_id": file_id,
            "ope_sys":sys,
            "path_num":5
        }
        # print(data)
        json_data = json.dumps(data)
        headers = {'Content-Type': 'application/json'}
        response = requests.post(url_filePath,headers=headers,data=json_data)
        if response.status_code != 200:
            print("获取文件蜜点部署路径失败")
            return False
        elif response.json()["code"] != 0 :
            print(f"获取文件蜜点部署路径失败:{response.json()['message']}")
            return False
        generate_path = response.json()["data"][:]
        print("获取文件蜜点部署路径成功")
        print("文件蜜点部署路径：")
        for i in range(len(generate_path)):
            print(str(i+1)+"."+generate_path[i])

        ### 部署文件&&传回部署信息
        path_num = input("选择要使用的路径（多个路径使用 , 隔开）：").split(",")
        with tqdm(total=len(path_num),desc="部署文件蜜点",leave=True,ncols=100) as pbar:
            for num in path_num:
                state = 0 # 初始化部署状态
                path = os.path.normpath(generate_path[int(num)-1])
                # 部署文件蜜点
                if os.path.exists(path): # 判断部署路径是否存在
                    pass
                else:
                    os.makedirs(path) # 不存在则创建
                ### 捕捉不到复制产生的异常
                # if sys == "Windows":  
                #     try:
                #         os.system("copy " + file_name + " " + path) # 复制文件
                #         print(f"部署文件 {file_name} 成功")
                #     except Exception as e:
                #         state = str(e)
                #         print(f"部署文件 {file_name} 失败，错误信息：{state}")
                # elif sys == "Linux":
                #     try:
                #         os.system("cp " + file_name + " " + path)
                #         print(f"部署文件 {file_name} 成功")
                #     except Exception as e:
                #         state = str(e)
                #         print(f"部署文件 {file_name} 失败，错误信息：{state}")

                try:
                    shutil.copy(file_name,path)
                    print(f"部署文件 {file_name} 成功")
                except Exception as e:
                    state = str(e)
                    print(f"部署文件 {file_name} 失败，错误信息：{state}")

                url_fileDeploy = hp_address + "/file/deploy"
                print(url_fileDeploy)
                data = {
                    "deploy_type":2,
                    "ip": socket.gethostbyname(socket.gethostname()), # 用户机ip
                    "path":path, # 文件蜜点部署路径
                    "machine_name": os.popen('hostname').read().strip(), # 用户机器名
                    "sys": sys, # 操作系统类型
                    "file_id":file_id,  # 文件蜜点id
                    "network":get_network_segment(), # 网段
                    "state":state # 部署状态
                }
                print(data)
                json_data = json.dumps(data)
                headers = {'Content-Type': 'application/json'}
                response = requests.post(url_fileDeploy,headers=headers,data=json_data)
                if response.status_code != 200:
                    print(f"传回部署信息失败,错误码:{response.status_code}")
                    continue
                else:
                    print("传回部署信息成功")
                    pbar.update(1)
        return True

    # 启动脚本
    def do_start(self,arg):
        isQuit = False


        # 打印配置信息
        print("蜜点管理服务器地址：" + hp_address)
        type_num = 1
        # 获取模板
        while True:
            type_num = input("选择模板类型序号(1.所有类型 2.docx 3.xlsx)：")
            if type_num == "1":
                self.do_getTemplate("")
                break
            elif type_num == "2":
                self.do_getTemplate("docx")
                break
            elif type_num == "3":
                self.do_getTemplate("xlsx")
                break
            else:
                print("输入序号有误，请重新输入")
                continue

        # 选择模板并部署
        while True:
            file_num = input("选择模板序号：")
            if not file_num:
                print("序号不能为空")
                continue
            elif file_num == "q":
                return True
            elif not isinstance(file_num, int):   # 判断是否为数字
                    print("序号必须为数字")
                    continue
            else:
                for num in file_num:
                    self.do_downloadFile(num)
                break
        print("部署完成")









    def do_quit(self,arg):
        return True
def send_machine_info():
    api_url = ""

    data = {
        "ip": socket.gethostbyname(socket.gethostname()),
        "path":"文件的路径",
        "machine_name": os.popen('hostname').read().strip(),
        "sys": os.name, # nt 为windows系统, posix为linux系统, mac为mac系统
    }
    json_data = json.dumps(data)

    headers = {
    'Content-Type': 'application/json'
    }

    cookies = {
        "Authorization": "Key"   #过网关需要cookie
    }

    response = requests.post(api_url, data=json_data, headers=headers,cookies=cookies)

# 检测ip是否合法
def is_valid_ipv4_address(address):
    #判断是否是合法ip
    try:
        socket.inet_pton(socket.AF_INET, address)
    except AttributeError:  # no inet_pton here, sorry
        try:
            socket.inet_aton(address)
        except socket.error:
            return False
        return address.count('.') == 3
    except socket.error:  # not a valid address
        return False
    return True

def download_file():
    #请求模板列表

    pass
    #用户选择模板
    pass
    #从文件蜜点仓库下载插入token的模板文件
    pass
    

def get_network_segment():
    # 获取当前主机名
    hostname = socket.gethostname()

    # 获取当前主机的IP地址
    ip = socket.gethostbyname(hostname)

    # 获取当前主机的网络接口信息
    interfaces = netifaces.interfaces()

    # 遍历网络接口，找到与当前IP地址匹配的接口
    for interface in interfaces:
        addresses = netifaces.ifaddresses(interface)
        if netifaces.AF_INET in addresses:
            for address in addresses[netifaces.AF_INET]:
                if 'addr' in address and address['addr'] == ip:
                    netmask = address['netmask']
                    network_segment = '.'.join([str(int(ip_octet) & int(netmask_octet)) for ip_octet, netmask_octet in zip(ip.split('.'), netmask.split('.'))])
                    return network_segment

    return None

# 调用函数获取当前主机所在的网段



if __name__=="__main__":


    agent = Agent()
    agent.cmdloop()