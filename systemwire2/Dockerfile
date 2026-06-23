# 基础镜像
FROM python:3.10.10-slim

# 设置工作目录
WORKDIR /app

# 拷贝依赖文件
COPY requirements.txt .

# 安装依赖
RUN pip install --no-cache-dir -r requirements.txt

# 拷贝项目代码
# 注意：.dockerignore 文件会忽略 .venv 等目录
COPY . .

# 暴露 Flask 端口
EXPOSE 5001

# 设置环境变量
ENV PYTHONUNBUFFERED=1

# 启动命令
CMD ["python", "app.py"]
