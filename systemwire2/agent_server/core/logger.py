# 日志配置器
import logging
from logging.handlers import RotatingFileHandler
import os

log_path = "log/"
# 确保日志文件的目录存在
if not os.path.exists(os.path.dirname(log_path)):
    os.makedirs(os.path.dirname(log_path))
    
def new_logger(logger_name:str,level):
        # 创建一个logger
    logger = logging.getLogger(logger_name)
    
    # 防止重复添加 handler
    if logger.hasHandlers():
        logger.handlers.clear()
    
    # 设置日志级别
    logger.setLevel(level)

    # 创建一个handler，用于写入日志文件（支持日志文件轮换）
    file_handler = RotatingFileHandler(
        os.path.join(log_path, logger_name + ".log"),
        maxBytes=10 * 1024 * 1024,  # 每个日志文件最大10MB
        backupCount=3               # 最多保留3个备份
    )
    file_handler.setLevel(logging.DEBUG)  # 文件记录所有日志级别

    # 创建一个handler，用于将日志输出到控制台
    console_handler = logging.StreamHandler()
    console_handler.setLevel(logging.INFO)  # 控制台只输出 INFO 及以上的日志

    # 设置日志格式
    formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
    file_handler.setFormatter(formatter)
    console_handler.setFormatter(formatter)

    # 给logger添加handler
    logger.addHandler(file_handler)
    logger.addHandler(console_handler)

    logger.propagate = False
    
    return logger