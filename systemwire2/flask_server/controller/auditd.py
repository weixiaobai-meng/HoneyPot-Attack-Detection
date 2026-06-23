import codecs

# 解析auditd的proctitle字段
def parse_proctitle(encoded_string):
    """Parse the prctitle field of an audit event."""
    decoded_string = codecs.decode(encoded_string, 'hex').decode('utf-8')
    # print(decoded_string)
    return decoded_string


######### syscall #########
# 时间戳 (msg字段): audit(1719303407.784:2259912)
# 1719303407.784: UNIX时间戳，表示事件发生的时间。
# 2259912: 审计事件的序列号。
# 进程信息:

# 命令名称 (comm字段): "auditctl"
# 可执行文件 (exe字段): "/usr/sbin/auditctl"
# 父进程ID (ppid字段): 1171923
# 进程ID (pid字段): 1171928
# 会话ID (ses字段): 244671
# 登录终端 (tty字段): pts2
# 权限和身份信息:

# 成功执行 (success字段): "yes"
# 退出码 (exit字段): "1076"
# 系统调用 (syscall字段): "44" (对应的是 execve 系统调用)
# 实际用户ID (uid字段): "0" (root用户)
# 有效用户ID (euid字段): "0"
# 会话用户ID (suid字段): "0"
# 文件系统用户ID (fsuid字段): "0"
# 其他信息:

# 主体 (subj字段): "unconfined" (安全上下文信息，通常指进程的安全上下文)
# 参数 (a0, a1, a2, a3字段): 分别对应系统调用的参数，可以根据具体系统调用的定义来解释。


######### path #########
# 文件系统对象信息:

# 项索引 (item字段): "0"
# 表示这是审计事件中的第一个条目。
# 名称 (name字段): "/home/cly/"
# 表示文件系统对象的路径名为 "/home/cly/"。
# 索引节点号 (inode字段): "1048577"
# 表示文件系统对象的索引节点号。
# 设备号 (dev字段): "fe:01"
# 表示文件系统对象所在的设备号。
# 访问权限 (mode字段): "040755"
# 表示文件系统对象的访问权限，以八进制表示。
# 所有者用户ID (ouid字段): "1004"
# 表示文件系统对象的所有者用户ID。
# 所有者组ID (ogid字段): "1004"
# 表示文件系统对象的所有者组ID。
# 设备类型 (rdev字段): "00:00"
# 表示文件系统对象的设备类型。
# 名称类型 (nametype字段): "PARENT"
# 表示文件系统对象的类型，这里是父级目录。
# 文件系统能力 (cap_fp, cap_fi, cap_fe, cap_fver, cap_frootid字段):
# 这些字段通常用于文件系统的能力描述，例如文件系统支持的特性或者能力标识