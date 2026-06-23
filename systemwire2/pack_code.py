import compileall
import datetime
import os
import shutil
import zipfile
from pathlib import Path


def modify_filename():
    # 如果没有__pycache__目录则创建
    directory = './__pycache__'
    if not os.path.exists(directory):
        os.makedirs(directory)
    files = os.listdir(directory)

    # 遍历文件并修改文件名
    for filename in files:
        if filename.endswith('.pyc'):  # 只修改以 .txt 结尾的文件名
            new_filename = filename.replace('.cpython-310.pyc', '.pyc')  # 修改文件名的逻辑
            old_path = os.path.join(directory, filename)
            new_path = os.path.join(directory, new_filename)
            os.rename(old_path, new_path)


def zip_directory(directory, zip_name):
    zipf = zipfile.ZipFile(zip_name, 'w', zipfile.ZIP_DEFLATED)
    for root, dirs, files in os.walk(directory):
        for file in files:
            file_path = os.path.join(root, file)
            zipf.write(file_path, os.path.relpath(file_path, directory))
    zipf.close()


def package(root_path="./"):
    """
    编译根目录下的包括子目录里的所有py文件成pyc文件到新的文件夹下
    如果只保留一份文件，请将需编译的目录备份，因为本程序会清空该源文件夹
    :param root_path: 需编译的目录
    :return:
    """
    root = Path(root_path)

    # 先删除根目录下的pyc文件和__pycache__文件夹
    for src_file in root.rglob("*.pyc"):
        os.remove(src_file)
    for src_file in root.rglob("__pycache__"):
        os.rmdir(src_file)

    current_day = datetime.date.today()  # 当前日期

    dest_path = Path(root.parent / f"{root.name}_{current_day}_01")  # 目标文件夹名称

    if os.path.exists(dest_path):
        shutil.rmtree(dest_path)

    # shutil.copytree(root, dest)

    compileall.compile_dir(root, force=True)  # 将项目下的py都编译成pyc文件

    for src_file in root.glob("**/*.pyc"):  # 遍历所有pyc文件
        relative_path = src_file.relative_to(root)  # pyc文件对应模块文件夹名称
        dest_folder = dest_path / str(relative_path.parent.parent)  # 在目标文件夹下创建同名模块文件夹
        os.makedirs(dest_folder, exist_ok=True)
        dest_file = dest_folder / (src_file.stem.rsplit(".", 1)[0] + src_file.suffix)  # 创建同名文件
        print(f"install {relative_path}")
        shutil.copyfile(src_file, dest_file)  # 将pyc文件复制到同名文件

    return dest_path


if __name__ == "__main__":
    # # 备份原有编译文件
    # if os.path.exists("./__pycache__"):
    #     if os.path.exists("./__pycache_backup__"):
    #         shutil.rmtree("./__pycache_backup__")
    #     shutil.copytree("./__pycache__", "./__pycache_backup__")
    # # 删除原有编译文件
    # if os.path.exists("./__pycache__"):
    #     shutil.rmtree("./__pycache__")
    # # 编译目录下所有py文件到 /__pycache__
    # compileall.compile_dir('./', force=True)
    # # 修改文件名
    # modify_filename()

    projiect_dir = os.path.abspath(os.path.dirname(__file__))
    zip_name = "pack_code_rebuild.zip"
    dest_path = package(root_path=projiect_dir)
    print(f"输出路径: {dest_path}")

    print("完成 pack_code_rebuild.zip")
    print(projiect_dir + "/" + zip_name)
    if os.path.exists(projiect_dir + "/" + zip_name):
        os.remove(projiect_dir + "/" + zip_name)

    zip_directory(dest_path, zip_name)

    # shutil.move(zip_name, projiect_dir)
    print("完成 pack_code_rebuild.zip")
