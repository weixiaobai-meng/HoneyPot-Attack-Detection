import compileall
import datetime
import os
import shutil
import zipfile
from pathlib import Path


def compile_project(root_path, temp_dir, ignore_dirs=None):
    """
    编译项目中的所有 .py 文件成 .pyc 文件，并将 .pyc 文件复制到 temp_dir 中
    :param root_path: 项目根路径
    :param temp_dir: 临时目录路径
    :param ignore_dirs: 忽略的目录列表
    :return: None
    """
    if ignore_dirs is None:
        ignore_dirs = []

    root = Path(root_path)
    temp_dir = Path(temp_dir)

    # 删除临时目录下的pyc文件和__pycache__文件夹
    for src_file in temp_dir.rglob("*.pyc"):
        os.remove(src_file)
    for src_file in temp_dir.rglob("__pycache__"):
        shutil.rmtree(src_file)

    compileall.compile_dir(root, force=True, legacy=True)  # 将项目下的py都编译成pyc文件

    for src_file in root.rglob("*.pyc"):  # 遍历所有pyc文件
        if not any(ignored in str(src_file) for ignored in ignore_dirs):
            relative_path = src_file.relative_to(root)  # pyc文件对应模块文件夹名称
            dest_folder = temp_dir / relative_path.parent  # 在临时文件夹下创建同名模块文件夹
            dest_folder.mkdir(parents=True, exist_ok=True)
            dest_file = dest_folder / src_file.name  # 创建同名文件
            shutil.copyfile(src_file, dest_file)  # 将pyc文件复制到同名文件


def copy_project_structure(root_path, temp_dir, ignore_dirs=None):
    """
    复制项目结构，将 .py 文件替换为 .pyc 文件
    :param root_path: 项目根路径
    :param temp_dir: 临时目录路径
    :param ignore_dirs: 忽略的目录列表
    :return: None
    """
    if ignore_dirs is None:
        ignore_dirs = []

    root = Path(root_path)
    temp_dir = Path(temp_dir)

    for item in root.rglob('*'):
        if any(ignored in str(item) for ignored in ignore_dirs):
            print(f"忽略: {item}")
        if not any(ignored in str(item) for ignored in ignore_dirs):
            relative_path = item.relative_to(root)
            dest_path = temp_dir / relative_path

            if item.is_dir():
                dest_path.mkdir(parents=True, exist_ok=True)
            elif item.suffix == '.py':
                # Skip copying .py files as they will be replaced with .pyc
                pass
            else:
                shutil.copyfile(item, dest_path)


def zip_directory(directory, zip_name):
    with zipfile.ZipFile(zip_name, 'w', zipfile.ZIP_DEFLATED) as zipf:
        for root, dirs, files in os.walk(directory):
            for file in files:
                file_path = os.path.join(root, file)    # 文件路径
                arcname = os.path.join('systemwire', os.path.relpath(file_path, directory)) 
                zipf.write(file_path, arcname)  # 写入zip文件


def pack_project(project_root_path="./", output_dir="./install", ignore_dirs=None):
    """
    编译并打包整个项目，将生成的zip文件放到指定目录下
    :param project_root_path: 项目根目录
    :param output_dir: 安装包目录
    :param ignore_dirs: 忽略的目录列表
    :return: None
    """
    if ignore_dirs is None:
        ignore_dirs = []

    root = Path(project_root_path)
    output_dir = Path(output_dir)
    current_day = datetime.date.today()  # 当前日期

    # 创建临时目录用于存放编译后的文件
    temp_dir = root / "temp" / "systemwire"
    if temp_dir.exists():
        shutil.rmtree(temp_dir)
    temp_dir.mkdir(parents=True, exist_ok=True)

    # 复制项目结构
    copy_project_structure(root, temp_dir, ignore_dirs=ignore_dirs)

    # 编译项目并复制 .pyc 文件
    compile_project(root, temp_dir, ignore_dirs=ignore_dirs)

    # 创建安装包目录
    output_dir.mkdir(parents=True, exist_ok=True)

    # 生成zip文件名
    zip_name = f"{root.name}-{current_day}.zip"
    zip_path = output_dir / zip_name

    # 如果zip文件存在则删除
    if zip_path.exists():
        zip_path.unlink()

    # 打包临时目录
    zip_directory(temp_dir, zip_path)

    # 删除临时目录
    shutil.rmtree(temp_dir)

    # 清理编译后的文件
    for src_file in root.rglob("*.pyc"):
        os.remove(src_file)
    
    print(f"打包完成: {zip_path}")

# 数据库初始化
def init_db():
    from app import flask_app
    from flask_server.exts import db
    with flask_app.app_context():
        db.create_all()

    print("数据库初始化完成")


if __name__ == "__main__":
    project_dir = Path(__file__).parent.absolute()
    output_dir = project_dir / "install"
    ignore_dirs = [
        ".git",
        ".idea",
        ".vscode",
        "venv",
        ".mypy_cache",
        "code_update",
        "email\\imap\\",
        "email\\pop3\\",
        "Honeyfiles\\generate\\",
        "Honeyfiles\\upload\\",
        "install",
        "migrations\\",
        "instance\\",
        "temp_pyc",
        "temp\\",
    ]
    
    pack_project(project_root_path=project_dir, output_dir=output_dir, ignore_dirs=ignore_dirs)
