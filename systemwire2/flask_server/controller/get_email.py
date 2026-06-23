import email
import imaplib
import os
import re
import poplib
import calendar
import email as emaill
from datetime import datetime, timedelta
from email import message_from_bytes
from email.header import decode_header
from email.parser import Parser
from email.utils import parseaddr, parsedate_to_datetime
from dateutil import parser
from flask import current_app
email_content = ""


# indent用于缩进显示:
def print_info(msg, indent=0):
    global email_content
    if indent == 0:
        for header in ["From", "To", "Subject", "Date", "Received"]:
            value = msg.get(header, "none")
            if value:
                if header == "Subject":
                    value = decode_str(value)
                if header == "Date":
                    value = parsedate_to_datetime(value)
                if header == "Received":
                    value = value.replace("\r\n", " ")
                if header == "From" or header == "To":
                    hdr, addr = parseaddr(value)
                    name = decode_str(hdr)
                    value = "%s <%s>" % (name, addr)

            email_content += "%s%s: %s\n" % ("  " * indent, header, value)
    if msg.is_multipart():
        parts = msg.get_payload()
        for n, part in enumerate(parts):
            # print('%spart %s' % ('  ' * indent, n))
            email_content += "%spart %s\n" % ("  " * indent, n)
            # print('%s--------------------' % ('  ' * indent))
            email_content += "%s--------------------\n" % ("  " * indent)
            print_info(part, indent + 1)
    else:
        content_type = msg.get_content_type()
        if content_type == "text/plain" or content_type == "text/html":
            content = msg.get_payload(decode=True)
            charset = guess_charset(msg)
            if charset:
                try:
                    content = content.decode(charset)
                except:
                    content = content.decode("utf-8")
                # print(len(content))
            # print('%sText: %s' % ('  ' * indent, content + '...'))
            email_content += "%sText: %s\n" % ("  " * indent, content + "...")
        else:
            # print('%sAttachment: %s' % ('  ' * indent, content_type))
            email_content += "%sAttachment: %s\n" % ("  " * indent, content_type)


def print_info_imap(email_message):
    global email_content
    # 提取邮件信息
    subject = email_message["Subject"]
    try:
        sender = parseaddr(email_message["From"])[1]
    except:
        sender = email_message["From"]
    recipients = parseaddr(email_message["To"])[1]
    date = email_message["Date"]
    header = email_message["Received"]
    body = ""
    # 提取邮件正文
    if email_message.is_multipart():
        for part in email_message.walk():
            content_type = part.get_content_type()
            if content_type == "text/plain":
                try:
                    body = part.get_payload(decode=True).decode()
                except:
                    body = part.get_payload(decode=True)
                break
    else:
        try:
            body = email_message.get_payload(decode=True).decode()
        except:
            body = email_message.get_payload(decode=True)
    # 打印邮件信息和正文
    print("From:", sender)
    print("To:", recipients)
    try:
        print("Subject:", decode_str(subject))
    except:
        print("Subject:", subject)
    print("Date:", date)
    print("Received:", header)
    if body != "":
        print("Body:")
        print(body)
    print("--------------------------------------")
    try:
        email_content += "From:" + sender + "\n"
    except:
        decoded_subject = decode_str(subject)
        email_content += "From:" + (decoded_subject if decoded_subject else "[Decoding Error]") + "\n"
    email_content += "To:" + recipients + "\n"
    try:
        decoded_subject = decode_str(subject)
        email_content += "Subject:" + (decoded_subject if decoded_subject else "[Decoding Error]") + "\n"
    except:
        email_content += "Subject:" + (subject if subject else "[Decoding Error]") + "\n"
    email_content += "Date:" + date + "\n"
    try:
        email_content += "Received:" + header + "\n"
    except:
        email_content += "Received: None\n"
    try:
        email_content += "Body:" + body + "\n"
    except:
        try:
            email_content += "Body:" + body.decode("gbk", errors="replace") + "\n"
        except UnicodeDecodeError:
            email_content += "Body: [Decoding Error]\n"

    email_content += "--------------------------------------\n"


# 根据decode_header()返回的编码信息，将邮件内容转换为字符串
def decode_str(s):
    value, charset = decode_header(s)[0]
    if charset:
        try:
            value = value.decode(charset)  # 将字符串转换为指定编码的字符串
        except:
            value = value.decode("utf-8")

    return value


def guess_charset(msg):
    charset = msg.get_charset()
    if charset is None:
        content_type = msg.get("Content-Type", "").lower()
        pos = content_type.find("charset=")
        if pos >= 0:
            charset = content_type[pos + 8:].strip()
    return charset


def get_email_pop3(email, password, pop3_server):  # 返回接收邮件的数量
    # from app import app #解决循环导入问题
    global email_content
    folder = os.path.exists(f'./email/pop3/{email.split("@")[0]}')
    if not folder:
        os.makedirs(f'./email/pop3/{email.split("@")[0]}')
    try:
        server = poplib.POP3_SSL(pop3_server, port=995, timeout=10)
        server.set_debuglevel(1)
        # print(server.getwelcome().decode('utf-8'))
        server.user(email)
        server.pass_(password)
        current_app.logger.info(f"{email} login email server(pop3) success")
    except poplib.error_proto as e:
        error_message = e.args[0].decode('gbk')
        print("邮箱登录失败: " + error_message)
        current_app.logger.error(f"{email} login email server(pop3) failed: {error_message}")
        return error_message, -1
    except Exception as e:
        error_message = str(e)
        print("未知错误: " + error_message)
        current_app.logger.error(f"{email} login email server(pop3) failed: {error_message}")
        return error_message, -1
    # stat()返回邮件数量和占用空间:
    # print('Messages: %s. Size: %s' % server.stat())

    resp, mails, octets = server.list()  # resp是状态码，mails是邮件列表(邮件id，邮件大小)，octets是邮件大小
    mail_count, _ = server.stat()
    index = len(mails)  # 账号中邮件数量
    num = len(os.listdir(f'./email/pop3/{email.split("@")[0]}'))  # 已经下载的邮件数量
    current_app.logger.info(f"[Email]: {email} , remote:{index} , local:{num}")
    # 当本地邮件数量小于远程邮件数量时，下载邮件
    if num < index:
        current_app.logger.info(f"Start pull email from server:")
        for i in range(num + 1, index + 1):
            resp, lines, octets = server.retr(i)  # lines是邮件内容，列表形式存储
            print(f"retr response: {resp.decode('utf-8')[:3]}")
            if resp.decode("utf-8")[:3] != "+OK":
                current_app.logger.error(f"{email} get {i} email failed:{resp.decode('utf-8')}")
                continue
            msg_content = b"\r\n".join(lines).decode("utf-8")
            msg = Parser().parsestr(msg_content)

            print_info(msg, indent=0)  # 打印邮件内容,将邮件内容写入email_content
            with open(f'./email/pop3/{email.split("@")[0]}/{email.split("@")[0]}_{i}.txt', "w", encoding="utf-8") as f:
                f.write(email_content)
            email_content = ""
        current_app.logger.info(f"{email} get {index - num} email success")
        server.quit()
        return None, index - num
    else:
        server.quit()
        return None, 0


def add_time(mail):
    try:
        # mail = mail.decode('UTF-8', errors='replace')
        get_date = re.search(r'Date:\s([A-Za-z]{1,3}),\s([0-9]{1,2})\s([A-Za-z]{1,3})\s([0-9]{1,4})\s([0-9]{1,2}):',
                             mail)
    except Exception as e:
        print(e)
    return '{}-{}-{} {}'.format(get_date.group(4), str(list(calendar.month_abbr).index(get_date.group(3))).zfill(2),
                                str(get_date.group(2)).zfill(2), get_date.group(5))


def get_email_pop3_test(email, password, pop3_server):  # 返回接收邮件的数量
    server = poplib.POP3_SSL(pop3_server, port=995, timeout=10)
    server.set_debuglevel(1)
    # 身份认证:
    server.user(email)
    server.pass_(password)
    # stat()返回邮件数量和占用空间:
    print('Messages: %s. Size: %s' % server.stat())

    resp, mails, octets = server.list()  # list()返回所有邮件的编号:
    mail_count, _ = server.stat()
    for i in range(mail_count):
        _, lines, _ = server.retr(i + 1)  # 获取邮件内容
        email_content = b'\n'.join(lines).decode('utf-8')
        msg = email.message_from_bytes(email_content)
        message_id = msg.get("Message-ID")
        # TODO:将MessageID作为文件名
        print(message_id)


def get_email_imap(username, password, imap_server_url):
    global email_content
    folder = os.path.exists(f'./email/imap/{username.split("@")[0]}')
    if not folder:
        os.makedirs(f'./email/imap/{username.split("@")[0]}')
    try:
        server = imaplib.IMAP4_SSL(imap_server_url)
        server.login(username, password)
        current_app.logger.info(f"{username} login email server(imap) success")
    except Exception as e:
        print(str(e))
        current_app.logger.error(f"{username} login email server(imap) failed:{str(e)}")
        return str(e), -1
    # print(server.list())

    # 网易邮箱验证问题
    imaplib.Commands["ID"] = ("AUTH",)
    args = (
        "name",
        username,
        "contact",
        username,
        "version",
        "1.0.0",
        "vendor",
        "myclient",
    )
    server._simple_command("ID", str(args).replace(",", "").replace("'", '"'))

    a, b = server.select("INBOX")
    current_app.logger.debug(a)
    current_app.logger.debug(b)
    # total_emails = int(server.stat()[1][0])  # 获取邮件总数
    # print(f"邮件总数:{total_emails}")

    # current_app.logger.debug(f"total emails: {total_emails}")

    typ, data = server.search(None, "ALL")
    email_ids = data[0].split()  # 获取邮件id列表
    new_email_count = len(email_ids)  # 获取邮件数量
    current_app.logger.debug(f"email count: {new_email_count}")
    print(f"邮件总数:{new_email_count}")

    local_email_count = len(os.listdir(f'./email/imap/{username.split("@")[0]}'))  # 获取该账号本地缓存的邮件数量

    if local_email_count < len(email_ids):
        for email_id in email_ids:
            resp, data = server.fetch(email_id, "(RFC822)")
            print("fetch resp: " + resp)
            if resp != "OK":
                current_app.logger.error(f"{username} get {email_id} email failed:{resp}")
                continue
            raw_email = data[0][1]
            # 解析邮件内容
            email_message = message_from_bytes(raw_email)
            print_info_imap(email_message)
            with open(f'./email/imap/{username.split("@")[0]}/{username.split("@")[0]}_{email_id.decode()}.txt', "w",
                      encoding="utf-8") as f:
                f.write(email_content)
            email_content = ""
            # break
        return None, len(email_ids) - local_email_count
    else:
        server.close()
        server.logout()
        return None, 0


def delete_email_imap(username, password, imap_server, email_id):
    # from initdb import app #解决循环导入问题
    folder = os.path.exists(f'./email/imap/{username.split("@")[0]}')
    if not folder:
        os.makedirs(f'./email/imap/{username.split("@")[0]}')
    try:
        server = imaplib.IMAP4_SSL(imap_server)
        server.login(username, password)
    except Exception as e:
        print(str(e))
        return str(e), -1
    print(f"server.list():\n{server.list()}")
    # ('OK', [b'() "/" "INBOX"', b'(\\Drafts) "/" "&g0l6P3ux-"', b'(\\Sent) "/" "&XfJT0ZAB-"', b'(\\Trash) "/" "&XfJSIJZk-"', b'(\\Junk) "/" "&V4NXPpCuTvY-"', b'() "/" "&dcVr0mWHTvZZOQ-"'])

    # 网易邮箱验证问题
    imaplib.Commands["ID"] = ("AUTH",)
    args = (
        "name",
        username,
        "contact",
        username,
        "version",
        "1.0.0",
        "vendor",
        "myclient",
    )
    server._simple_command("ID", str(args).replace(",", "").replace("'", '"'))

    a, b = server.select("INBOX")
    print(f"server.select state: {a}")
    print(f"serevr.select data: {b}")

    typ, data = server.search(None, "ALL")
    if typ == "OK":
        email_ids = data[0].split()
        print(len(email_ids))
        for i in range(len(email_ids)):
            if i == email_id - 1:
                print("Delete email -----------")
                print("Delete state: ")
                resp, msg = server.store(email_ids[i], "+FLAGS", "\\Deleted")
                print(resp)
                if resp != "OK":
                    current_app.logger.error(
                        f"{username} delete {email_id} email failed:{resp}"
                    )
                    return resp, -1
        current_app.logger.info(f"{username} delete index {email_id} email success")
        server.expunge()
    server.close()
    return "OK", 0


def delete_email_pop3(username, password, pop3_server, message_id):
    # 连接到 POP3 服务器
    pop_conn = poplib.POP3_SSL(pop3_server)
    pop_conn.user(username)
    pop_conn.pass_(password)

    # 获取邮箱中的邮件数量和大小
    mail_count, _ = pop_conn.stat()

    # 遍历邮箱中的所有邮件
    for i in range(mail_count):
        # 获取邮件内容
        _, lines, _ = pop_conn.retr(i + 1)
        email_content = b'\n'.join(lines).decode('utf-8')
        msg = email.message_from_bytes(email_content)
        message_id = msg.get("Message-ID")
        print("Message-ID:", message_id)
        # TODO:根据MessageID删除邮件
        # 如果邮件满足删除条件，将其标记为删除状态
        if message_id == msg.get("Message-ID"):  # 根据需要修改删除条件
            pop_conn.dele(i + 1)
            print(f"Marked email {i + 1} for deletion")

    # 退出连接时，服务器会删除所有标记为删除状态的邮件
    pop_conn.quit()


if __name__ == "__main__":
    email1 = "chenglytest@163.com"
    email2 = "langctest2@163.com"
    password1 = "JMDAXFUEWGAHYJVK"
    password2 = "BHTZTSHKKFTTYGDH"
    pop3_server = "pop.163.com"
    imap_server = "imap.163.com"
    # try:
    #     get_email_pop3_test(email1, password1, pop3_server)
    # except Exception as e:
    #     print("Error:", e.args[0].decode('gbk', 'ignore'))
    # if b'hello' == 'hello'.encode():
    #     print("True")
    try:
        get_email_imap(email1, password1, imap_server)
    except Exception as e:
        print("Error:", e.args[0].decode('gbk', 'ignore'))
