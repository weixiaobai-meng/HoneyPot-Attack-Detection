import os


def read_file(filename):
    if os.path.exists(filename):
        with open(filename, 'r', encoding="utf-8") as target:
            data = target.readlines()
            return [d.strip() for d in data]
    else:
        print("文件不存在：" + filename)
        return []


basedir = os.path.dirname(__file__)

time_format_file = os.path.join(basedir, "time_format.txt")

TIME_FORMAT = read_file(time_format_file)