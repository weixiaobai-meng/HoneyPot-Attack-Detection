import json
import linecache
import email.utils
from flask_server.filter import keyword_filter, sender_filter


def analyze_email(mail_path):
    with open(mail_path, 'r', encoding="utf-8") as f:
        text = f.read()  # 读取文本文件
    sender = linecache.getline(mail_path, 1).split(":")[1].strip()
    subject = linecache.getline(mail_path, 3).split(":")[1].strip()
    time_str = ":".join(linecache.getline(mail_path, 4).split(":")[1:]).strip()
    # print(datetime.strptime(time_str, '%Y-%m-%d %H:%M:%S%z'))
    header = linecache.getline(mail_path, 5).split(":")[1].strip()
    name, email_address = email.utils.parseaddr(sender)

    sender_type = sender_filter(email_address)  # 发件人过滤
    target_kwywords_list = keyword_filter(text)  # 关键字过滤
    if sender_type == 1:    # 1: 白名单 2: 黑名单
        return False, email_address, subject, time_str, header, None
    if target_kwywords_list is None or len(target_kwywords_list) != 0:
        pfish = True
    else:
        pfish = False

    parser_info = {
        'keywords': target_kwywords_list,
        'block': sender_type
    }
    return pfish, email_address, subject, time_str, header, parser_info


if __name__ == "__main__":
    path = "../../email/pop3/zhangsan/zhangsan_1.txt"
    res = analyze_email(path)
    print(json.dumps(res, indent=4))
