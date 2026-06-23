#!/bin/bash

# 简化版蜜罐系统部署脚本
echo "开始部署蜜罐系统到 /root/honeypot/"

# 创建目录
mkdir -p /root/honeypot/{deploy_package,files,logs}

# 复制文件
cp server.py /root/honeypot/deploy_package/
cp deployments.json /root/honeypot/deploy_package/
cp requirements.txt /root/honeypot/deploy_package/
cp nginx_honeypot.conf /root/honeypot/deploy_package/

# 安装依赖
cd /root/honeypot/deploy_package
pip3 install -r requirements.txt

# 创建systemd服务
cat > /etc/systemd/system/honeypot.service << 'EOF'
[Unit]
Description=Honeypot Server
After=network.target

[Service]
Type=simple
User=root
WorkingDirectory=/root/honeypot/deploy_package
ExecStart=/usr/bin/python3 server.py
Restart=always

[Install]
WantedBy=multi-user.target
EOF

# 配置nginx
cp nginx_honeypot.conf /etc/nginx/sites-available/honeypot
ln -sf /etc/nginx/sites-available/honeypot /etc/nginx/sites-enabled/
nginx -t

# 启动服务
systemctl daemon-reload
systemctl enable honeypot
systemctl start honeypot
systemctl reload nginx

echo "部署完成！"
echo "使用方法："
echo "1. 将蜜罐文件放到 /root/honeypot/files/目录名/"
echo "2. 在 deployments.json 中配置域名映射"
echo "3. systemctl restart honeypot"