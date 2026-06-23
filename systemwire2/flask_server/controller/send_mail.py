import email
import imaplib
import poplib
import smtplib
from email.mime.application import MIMEApplication
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText

# 发邮件
def send_mail():
    # 邮件配置
    smtp_server = "smtp.163.com"  # SMTP 服务器地址
    smtp_port = 25  # SMTP 服务器端口号
    smtp_username = "chenglytest"  # SMTP 服务器用户名
    smtp_password = "AMIYOTOBXEVKJCVM"  # SMTP 服务器密码
    sender_email = "chenglytest@163.com"  # 蜜点邮箱

    receiver_email = "1026883034@qq.com"  # 收件人邮箱

    # 创建包含邮件内容的消息对象
    msg = MIMEMultipart()
    msg["From"] = sender_email  # 发件人邮箱
    msg["To"] = receiver_email  # 收件人邮箱
    msg["Subject"] = "回复测试"  # 邮件主题

    # 添加邮件正文
    # 1.html正文
    content_html = """
                <html>
                <body>
                    <p>这是一封带有图片的邮件：</p>
                    <p><img src="https://test.cfly.top/1px.png"></p>
                </body>
                </html>
                """
    msg.attach(MIMEText(content_html, "html", "utf-8"))  # 添加 HTML 格式正文
    # 2.纯文本正文
    # content_plain = "领导，这是你要的文件"
    # msg.attach(MIMEText(content_plain, "plain"))

    # 添加附件
    honey_file = "Honeyfiles/generate/人身损害赔偿和解协议-FTaXb.docx"
    filename = honey_file.split("/")[-1]
    with open(honey_file, "rb") as file:
        attachment = MIMEApplication(file.read(), _subtype="docx")
        attachment.add_header("Content-Disposition", "attachment", filename=filename)
        msg.attach(attachment)

    try:
        with smtplib.SMTP(smtp_server, smtp_port) as server:
            server.starttls()  # 开启 TLS 加密
            server.login(smtp_username, smtp_password)  # 登录 SMTP 服务器
            server.send_message(msg)  # 发送邮件
            server.quit()
        print("邮件发送成功")
    except smtplib.SMTPException as e:
        print("邮件发送失败:", str(e))


# 回复邮件1
def reply_email_imap():
    # 连接到 IMAP 服务器
    imap_server = imaplib.IMAP4("imap.example.com")
    imap_server.login("your_username", "your_password")
    imap_server.select("INBOX")

    # 搜索特定邮件主题
    _, message_ids = imap_server.search(None, 'SUBJECT "特定邮件主题"')

    if message_ids[0]:
        # 获取邮件内容
        _, msg_data = imap_server.fetch(message_ids[0], "(RFC822)")
        raw_email = msg_data[0][1]
        email_message = email.message_from_bytes(raw_email)

        # 提取发件人和邮件内容
        sender = email.utils.parseaddr(email_message["From"])[1]
        body = ""

        if email_message.is_multipart():
            for part in email_message.walk():
                content_type = part.get_content_type()
                if content_type == "text/plain":
                    body = part.get_payload(decode=True).decode("utf-8")
                    break
        else:
            body = email_message.get_payload(decode=True).decode("utf-8")

        # 构建回复邮件
        reply_subject = "Re: " + email_message["Subject"]
        reply_body = "这是回复的内容"
        reply_message = MIMEText(reply_body)
        reply_message["Subject"] = reply_subject
        reply_message["From"] = "your_email@example.com"
        reply_message["To"] = sender

        # 连接到 SMTP 服务器并发送回复邮件
        smtp_server = smtplib.SMTP("smtp.example.com")
        smtp_server.login("your_username", "your_password")
        smtp_server.send_message(reply_message)
        smtp_server.quit()

        return "回复邮件已发送"

    return "未找到符合条件的邮件"


def reply_email_pop(server, username, password, subject, sender):
    # 连接到 POP3 服务器
    pop_server = poplib.POP3(server)
    pop_server.user(username)
    pop_server.pass_(password)

    # 根据邮件主题和发件人搜索邮件
    num_messages = len(pop_server.list()[1])
    for i in range(num_messages, 0, -1):    # 倒序遍历邮件
        _, msg_lines, _ = pop_server.retr(i)
        msg_content = b"\r\n".join(msg_lines).decode("utf-8")
        email_message = email.message_from_string(msg_content)
        if email_message["Subject"] == subject and email_message["From"] == sender:
            # 提取邮件内容
            body = ""

            if email_message.is_multipart():
                for part in email_message.walk():
                    content_type = part.get_content_type()
                    if content_type == "text/plain":
                        body = part.get_payload(decode=True).decode("utf-8")
                        break
            else:
                body = email_message.get_payload(decode=True).decode("utf-8")

            # 构建回复邮件
            reply_subject = "Re: " + email_message["Subject"]
            reply_body = "这是回复的内容"
            reply_message = MIMEText(reply_body)
            reply_message["Subject"] = reply_subject
            reply_message["From"] = "your_email@example.com"
            reply_message["To"] = sender

            # 连接到 SMTP 服务器并发送回复邮件
            smtp_server = smtplib.SMTP("smtp.example.com")
            smtp_server.login("your_username", "your_password")
            smtp_server.send_message(reply_message)
            smtp_server.quit()

            return "回复邮件已发送"
    return "未找到邮件"


if __name__ == "__main__":
    send_mail()
