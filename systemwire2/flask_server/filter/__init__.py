import os
import re
from urllib.parse import urlparse


def read_file(filename):
    if os.path.exists(filename):
        with open(filename, 'r', encoding="utf-8") as target:
            data = target.readlines()
            return [d.strip() for d in data]
    else:
        print("文件不存在：" + filename)
        return []


basedir = os.path.dirname(__file__)

# 黑名单
block_keywords_file = os.path.join(basedir, 'block', 'keywords.txt')
block_domain_file = os.path.join(basedir, 'block', 'domains.txt')
block_short_domain_file = os.path.join(basedir, 'block', 'short_domains.txt')
block_sender_file = os.path.join(basedir, 'block', 'email_sender.txt')

BLOCK_KEYWORDS = read_file(block_keywords_file)
BLOCK_DOMAINS = read_file(block_domain_file)
BLOCK_SHORT_DOMAINS = read_file(block_short_domain_file)
BLOCK_SENDER = read_file(block_short_domain_file)

# 白名单
white_sender_file = os.path.join(basedir, 'white', 'email_sender.txt')
white_domain_file = os.path.join(basedir, 'white', 'domains.txt')

WHITE_SENDER = read_file(white_sender_file)
WHITE_DOMAIN = read_file(white_domain_file)


def check_filter_domain(http_url):
    """
    domain过滤检测，仅检测二级或者三级域名
    返回值：
    True：过滤
    False：不过滤单
    """
    uri = urlparse(http_url)
    domain_name = f"{uri.netloc}"
    domain_list = domain_name.split(':')[0].split('.')
    if len(domain_list) < 2:
        return True
    elif len(domain_list) > 2 and domain_list[-2] in ['com', 'org', 'net', 'int', 'edu', 'gov', 'co']:
        # 取三级域名
        new_domain_name = '.'.join(domain_list[-3:])
    else:
        # 取二级域名
        new_domain_name = '.'.join(domain_list[-2:])
    if new_domain_name in BLOCK_DOMAINS:
        return True
    return False


# 文本过滤
def keyword_filter(text, full_match=False):
    target_list = []  # 命中列表
    for keyword in BLOCK_KEYWORDS:  # 使用正则表达式查找关键词
        if re.search(keyword, text, re.IGNORECASE):
            target_list.append(keyword)
            if full_match:  # 对所有关键字进行匹配
                continue
            else:
                break
    return target_list

# 邮件发送人过滤
def sender_filter(sender):
    """
    发送人过滤
    参数：发送人sender
        对邮件发送人进行过滤，检查发送人是否在发送人黑名单或域黑名单，亦或者属于白名单
    返回：
        若输入白名单或不在黑名单则返回 False
        否则返回 True
    （白名单优先级大于黑名单）
    """
    sender_domain = sender.split('@')[-1]
    if sender in WHITE_SENDER or sender_domain in WHITE_DOMAIN:  # 白名单检测
        return 1
    if sender in BLOCK_SENDER or sender_domain in BLOCK_DOMAINS:  # 黑名单检测
        return 2

    return 0  # 未在名单中
