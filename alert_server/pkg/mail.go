package pkg

import (
	"bytes"
	"encoding/json"
	"fmt"
	"html/template"
	"io"
	"net/http"
	"net/smtp"
	"net/url"
	"strings"
	"time"
)

type mail struct {
	userName   string
	passWord   string
	mailServer string
	sendTo     string
	subject    string
	body       string
	bodyhtml   string
}

func SendTemplateMail(alertMessage, agent, triggerTime, token, ipAddress string, alertReceiverList []string) error {
	from := "alert@goand.top"      // 发送邮箱
	emailPassword := "alert@2024." // 发送邮箱密码
	smtpHost := "mail.goand.top"   // 邮箱服务器地址
	smtpPort := "587"              // 邮箱服务器端口
	auth := smtp.PlainAuth("", from, emailPassword, smtpHost)
	// fmt.Println("auth:", auth)
	to := Cfg.AdminEmails // 管理员邮箱
	if len(alertReceiverList) != 0 {
		to = append(to, alertReceiverList...) // 添加接收邮箱
	}
	subject := "文件告警"
	charset := "UTF-8"

	// 准备模板数据
	data := struct {
		Message   string
		Agent     string
		Time      string
		Token     string
		IpAddress string
	}{
		Message:   alertMessage,
		Agent:     agent,
		Time:      triggerTime,
		Token:     token,
		IpAddress: ipAddress,
	}

	var body bytes.Buffer

	t, err := template.ParseFiles("templates/email1.html") // 解析模板文件
	if err != nil {
		println("模板解析出错")
		return err
	}
	if err := t.Execute(&body, data); err != nil { // 渲染模板
		println("模板渲染出错")
		return err
	}

	// 设置邮件头
	headers := make(map[string]string)
	headers["From"] = from
	headers["To"] = strings.Join(to, ", ")
	headers["Subject"] = subject
	headers["MIME-Version"] = "1.0"
	headers["Content-Type"] = "text/html; charset=" + charset

	var message bytes.Buffer

	for key, value := range headers {
		message.WriteString(key)
		message.WriteString(": ")
		message.WriteString(value)
		message.WriteString("\r\n")
	}
	message.WriteString("\r\n")
	message.Write(body.Bytes())

	// 连接到Mailu服务器的SMTP接口
	err = smtp.SendMail(smtpHost+":"+smtpPort, auth, from, to, message.Bytes())
	if err != nil {
		fmt.Println("Failed to send email:", err)
		return err
	}
	return nil
}

// smtp 发送邮件
func sendMail(userName, password, mailServer, to, subject, body, mailType string) error {
	mail1 := mail{
		"362370465@qq.com",
		"xepbmvndztqybhje",
		"smtp.qq.com:25",
		"362370465@qq.com",
		"测试邮件",
		`服务存在异常`,
		`<html>
					<body>
						<h1>服务存在异常</h1>
					<\body>
				 <\html>`}
	fmt.Println("发送邮件")
	var err error
	err = sendMail(mail1.userName, mail1.passWord, mail1.mailServer, mail1.sendTo, mail1.subject, mail1.body, "")
	if err != nil {
		fmt.Println("发送邮件失败")
		fmt.Println(err)
	} else {
		fmt.Println("发送邮件成功")
	}
	//拼接消息体
	var contentType string
	if mailType == "html" {
		contentType = "Content-Type: text/" + mailType + "; charset=UTF-8"
	} else {
		contentType = "Content-Type: text/plain" + "; charset=UTF-8"
	}

	msg := []byte("To: " + to + "\r\nFrom: " + userName + "\r\nSubject: " + subject + "\r\n" + contentType + "\r\n\r\n" + body)

	//消息内容查看
	fmt.Println("To: " + to + "\r\n" +
		"From: " + userName + "\r\n" +
		"Subject: " + subject + "\r\n" +
		"" + contentType + "\r\n\r\n" +
		"" + body)

	fmt.Println(msg)

	//身份认证
	hp := strings.Split(mailServer, ":")
	auth := smtp.PlainAuth("", userName, password, hp[0])

	sendTo := strings.Split(to, ":")
	err = smtp.SendMail(mailServer, auth, userName, sendTo, msg)

	return err

}

// json
func Api_send_mail() bool {
	var api_url string = "https://api.sendcloud.net/apiv2/mail/send"
	var params map[string]string = make(map[string]string)

	params["apiUser"] = "sc_y8mzml_test_JL2Csq"
	params["apiKey"] = "aad771dd2597c2d9af0d08b40da59bb8"
	params["from"] = "service@sendcloud.im"
	params["fromName"] = "文档打开告警"
	params["to"] = "362370465@qq.com"
	params["subject"] = "文档追踪提示邮件"
	params["html"] = "这是一个告警信息，您的文档已经被打开了"
	//fmt.Println(params)
	marshal, err := json.Marshal(params)
	if err != nil {
		fmt.Printf("Map转化为bytes数组失败，异常%s\n", err)
		return false
	}
	// fmt.Println("Map转化为bytes数组成功，%v\n", marshal)
	// marshal_str := string(marshal)
	// fmt.Println("Bytes转换为json串成功：%s\n", marshal_str)

	req, err := http.NewRequest("POST", api_url, bytes.NewBuffer(marshal))
	fmt.Println(req.Body)
	req.Header.Set("Content-Type", "application/json")
	// req.Header.Set("Content-Type", "application/x-www-form-urlencoded/json")
	req.Header.Set("User-Agent", "AppleWebKit/537.36 (KHTML, like Gecko) Version/4.0")
	client := &http.Client{}

	res, err := client.Do(req)
	if err != nil {
		panic(err)
	}
	defer res.Body.Close()

	fmt.Println("status:", res.Status)
	fmt.Println("response:", res.Header)
	body, _ := io.ReadAll(res.Body)
	fmt.Println("response body:", string(body))
	return true

}

func PostForm(url string, data url.Values) (string, error) {
	resp, err := http.PostForm(url, data)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	content, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}
	return string(content), nil
}

// postform fmt.sprintf，使用云邮件api发送警报邮件
func send_mail(addr, msg, ip_addr, agent, token string) (string, error) {
	var api_url string = "https://api.sendcloud.net/apiv2/mail/sendtemplate"
	var response string
	var err error
	now := time.Now()
	yearMon := now.Format("2006-01-02")
	timeNow := now.Format("2006-01-02 15:04:05.000 Mon Jan")
	xsmtpapiData := fmt.Sprint("{\"to\": [\"", addr, "\"],\"sub\": {\"%date%\": [\"", yearMon, "\"],\"%time_now%\":[\"", timeNow, "\"],\"%message%\":[\"", msg, "\"],\"%ip_addr%\":[\"", ip_addr, "\"],\"%agent%\":[\"", agent, "\"],\"%token%\":[\"", token, "\"]}}")

	data := url.Values{}
	data.Set("templateInvokeName", "alert_info")           //需填入模板InvokeName
	data.Set("apiUser", "sc_y8mzml_test_JL2Csq")           //需填入apiuser
	data.Set("apiKey", "aad771dd2597c2d9af0d08b40da59bb8") //需填入apikey
	data.Set("from", "service@sendcloud.im")
	data.Set("fromName", "文档打开告警")
	data.Set("to", addr)
	data.Set("subject", "文档追踪提示邮件")
	data.Set("xsmtpapi", xsmtpapiData)
	response, err = PostForm(api_url, data)
	return response, err

}
