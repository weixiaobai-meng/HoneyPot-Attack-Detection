"""
文件远程部署
"""
import paramiko

### 单台设备部署
# 选择部署的目标设备(network,ip)
# 获取ssh账号密码
# 生成路径
# 选择蜜点文件

# 登录ssh
# 记录scp状态，启动scp
# 记录原本权限，配置文件夹权限
# scp传输文件
# 恢复文件夹权限
# 关闭scp
#####################


### 多台设备部署
# 批量选择部署的目标设备(network,ip)
# 导入ssh账号密码配置
# 生成路径
# 选择蜜点文件
# 根据所选蜜点文件生成与目标数相同的蜜点文件

# 登录ssh
# 记录scp状态，启动scp
# 记录原本权限，配置文件夹权限
# scp传输文件
# 恢复文件夹权限
# 关闭scp
#####################


def file_auto_deploy():
    # 登录ssh
    hostname = '192.168.64.130'
    port = 22
    username = 'kali'
    password = 'kali'
    known_hosts_file = '../../data/.ssh/known_hosts'
    ssh_client = paramiko.SSHClient()
    ssh_client.load_host_keys(known_hosts_file) # 加载本机的HostKeys
    ssh_client.set_missing_host_key_policy(paramiko.AutoAddPolicy())    # 允许连接不在know_hosts文件中的主机

    try:

        ssh_client.connect(hostname, port, username, password)

        print('连接成功')
        # 在连接上执行命令
        stdin, stdout, stderr = ssh_client.exec_command('ls -l')
        print(stdout.read().decode())

        # stdin, stdout, stderr = ssh_client.exec_command('mkdir test && chmod 777 test && cd test')
        # print(stdout.read().decode())
        # print(stderr.read().decode())

        # 下载文件
        stdin, stdout, stderr = ssh_client.exec_command('curl -X POST -d "id=4" -o test.txt https://www.baidu.com')

        stdin, stdout, stderr = ssh_client.exec_command('ls -l')
        print(stdout.read().decode())


    except Exception as e:
        print('连接失败', e)
        return False

    finally:
        ssh_client.close()
        print('连接关闭')
    return


    # 记录scp状态，启动scp
    # 记录原本权限，配置文件夹权限
    # scp传输文件
    # 恢复文件夹权限
    # 关闭scp
    pass


if __name__ == "__main__":
    file_auto_deploy()