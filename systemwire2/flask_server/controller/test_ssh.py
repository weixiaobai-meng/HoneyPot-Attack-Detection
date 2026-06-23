# -*- coding: utf-8 -*-
import os
import paramiko

# 通过注册表检测是否安装xshell软件
def check_xshell_registry():
    import winreg
    try:
        key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r'Software\Microsoft\Windows\CurrentVersion\Uninstall\Xshell_is1')
        print('检测到xshell已安装')
    except FileNotFoundError:
        print('未检测到xshell已安装')
    # finally:
    #     winreg.CloseKey(key)


import subprocess


def is_software_installed(software_name):
    # 使用wmic命令来查询安装的程序
    cmd = ['wmic', 'product', 'get', 'name']
    process = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    stdout, stderr = process.communicate()

    # 将输出转换为小写，便于比较
    installed_software_list = [name.lower() for name in stdout.splitlines() if name]
    # bytes to str
    installed_software_list = [name.decode() for name in installed_software_list]
    # 检查软件名是否在列表中
    return software_name.lower() in installed_software_list



if __name__ == '__main__':
    # 使用函数检查Notepad++是否安装
    software_name = "xshell 7"
    is_installed = is_software_installed(software_name)
    print(f"{software_name} is installed: {is_installed}")

