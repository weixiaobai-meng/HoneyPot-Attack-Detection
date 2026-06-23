# 系统蜜点

## 1. 环境配置

- python 版本要求: 3.10.x （建议>=3.10.10）
  

#### 1.安装python

windows-64 :[python 3.10.10 安装包下载](https://www.python.org/ftp/python/3.10.10/python-3.10.10-amd64.exe)

#### 2.配置虚拟环境

创建python虚拟环境，在本项目目录下运行命令：

```powershell
python -m venv venv
```

激活虚拟环境：

```
.\venv\Scripts\activate
```

激活成功后命令行前会有`(venv)`的标识

#### 3.导入依赖包

本项目已将所需依赖包导出至`requirements.txt`文件

在激活虚拟环境的情况下运行以下命令：

```
pip install -r requirements.txt -i https://mirrors.tuna.tsinghua.edu.cn/pypi/web/simple
```

命令解释：

-r 指定依赖包列表

-i 使用镜像源




## 2. 代码结构

- ***app.py：主程序入口**
- ***config.ini：主要配置文件**
- ***flask_server/：Flask后端主要代码**
  - ***view.py 视图文件(接口)**
  - models.py：     模型文件(数据库)
  - exts.py：       插件
  - ***controller/：   控制器文件夹（功能代码）**
  - log/：          日志文件夹
  - ***utils：         通用功能代码文件夹**
- agent_server/: 探针服务器
- config/：其他配置文件夹
- data/：其他数据文件夹
- email/：邮件缓存文件夹
- Honeyfiles/：蜜罐文件夹
- 'install/': 安装包
- 'instance/'：数据库文件夹
- 'logs/'：日志文件夹
- 'migration/'：数据库迁移文件夹(数据库表结构修改时使用)
- 'temp'：临时文件夹
- 'templates/'：文件模板文件夹

## 3. 开发调试环境

- IDE集成开发环境(二选一)：
  - pycharm
  - vscode
- API接口调试工具：
  - apifox

## 4. 代码逻辑

app.py：主程序入口

调用关系：
app -> create_flask_app() & create_grpc_server() -> 启动flask & 启动grpc server ->  views -> models -> db

创建app -> 读取接口代码 -> 读取数据库模型代码


## 其他
### 1. 数据库迁移
当数据表的定义发生修改或变化后，需要对数据库进行迁移，让数据存到新的表结构。
需要运行如下命令（在项目根目录下）：

(1) 第一次迁移需要先初始化：
```
flask db init
```
初始化完成后会在项目根目录下生成`migrations`文件夹，里面会记录每个版本的数据表变化信息

(2) 进行数据库迁移：
```
flask db migrate
```
这一步是从models代码中识别出需要修改的部分

(3) 进行表升级
```
flask db upgrade
```
按照修改的内容对数据库的结构进行改变，并自动将原有数据进行迁移

> 注意：
- 新加字段的时候尽量设置默认值，或者设置为可null

如果迁移时发现异常可是删除迁移数据重新迁移：
1. 删除migrations文件夹
2. 删除数据库的一个表：alembic_version
3. 重新按照步骤进行初始化和迁移

### 编译grpc
安装库
```
pip install grpcio-tools
```
编译命令
```
python -m grpc_tools.protoc -I. --python_out=. --grpc_python_out=. agent.proto
```