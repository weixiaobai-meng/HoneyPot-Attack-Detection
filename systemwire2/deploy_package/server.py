#!/usr/bin/env python3
"""
蜜罐部署服务器
用于部署到 /root/honeypot/ 目录结构
"""

from flask import Flask, request, send_from_directory, abort, jsonify
import os
import json
import logging
from datetime import datetime

app = Flask(__name__)

# 路径配置
FILES_DIR = '/root/honeypot/files'  # 蜜罐文件存放目录
CONFIG_FILE = '/root/honeypot/deploy_package/deployments.json'  # 配置文件
LOG_DIR = '/root/honeypot/logs'  # 日志目录

# 确保目录存在
os.makedirs(FILES_DIR, exist_ok=True)
os.makedirs(LOG_DIR, exist_ok=True)
os.makedirs(os.path.dirname(CONFIG_FILE), exist_ok=True)

# 配置日志
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler(os.path.join(LOG_DIR, 'server.log')),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

def load_deployments():
    """加载部署配置"""
    if os.path.exists(CONFIG_FILE):
        try:
            with open(CONFIG_FILE, 'r', encoding='utf-8') as f:
                return json.load(f)
        except:
            return {}
    return {}

def get_deployment_info(domain):
    """根据域名获取部署信息"""
    deployments = load_deployments()
    
    # 直接匹配域名
    if domain in deployments:
        return deployments[domain]
    
    # 如果没有找到，检查是否有通配符匹配
    for key, value in deployments.items():
        if key.startswith('*.') and domain.endswith(key[1:]):
            return value
    
    return None

@app.route('/files/<path:filename>')
def download_file(filename):
    """下载蜗宿文件"""
    domain = request.headers.get('Host', '').split(':')[0]
    
    # 获取部署信息
    deployment_info = get_deployment_info(domain)
    if not deployment_info:
        logger.warning(f"未找到域名 {domain} 对应的部署配置")
        abort(404)
    
    deployment_id = deployment_info['deployment_id']
    deployment_dir = os.path.join(FILES_DIR, deployment_id)
    
    # 记录下载日志
    client_ip = request.headers.get('X-Forwarded-For', request.remote_addr)
    user_agent = request.headers.get('User-Agent', '')
    logger.info(f"文件下载记录 - 域名: {domain}, IP: {client_ip}, 文件: {filename}, UA: {user_agent}")
    
    # 直接从部署目录下载文件（不需要files子目录）
    file_path = os.path.join(deployment_dir, filename)
    
    # 安全检查
    if not os.path.abspath(file_path).startswith(os.path.abspath(deployment_dir)):
        logger.warning(f"路径遍历攻击尝试: {filename}")
        abort(403)
    
    # 检查文件是否存在
    if os.path.isfile(file_path):
        return send_from_directory(deployment_dir, filename, as_attachment=True)
    else:
        logger.warning(f"下载文件不存在: {file_path}")
        abort(404)

@app.route('/')
@app.route('/<path:filename>')
def serve_honeypot(filename=''):
    """服务蜜罐页面和文件"""
    domain = request.headers.get('Host', '').split(':')[0]
    
    # 记录访问日志
    client_ip = request.headers.get('X-Forwarded-For', request.remote_addr)
    user_agent = request.headers.get('User-Agent', '')
    logger.info(f"访问记录 - 域名: {domain}, IP: {client_ip}, UA: {user_agent}, 路径: /{filename}")
    
    # 获取部署信息
    deployment_info = get_deployment_info(domain)
    if not deployment_info:
        logger.warning(f"未找到域名 {domain} 对应的部署配置")
        abort(404)
    
    deployment_id = deployment_info['deployment_id']
    deployment_dir = os.path.join(FILES_DIR, deployment_id)
    
    if not os.path.exists(deployment_dir):
        logger.error(f"部署目录不存在: {deployment_dir}")
        abort(404)
    
    # 如果没有指定文件名，返回主页
    if not filename:
        filename = deployment_info.get('main_file', 'downloads.html')
    
    try:
        # 构建完整的文件路径
        file_path = os.path.join(deployment_dir, filename)
        
        # 安全检查：确保文件在部署目录内
        if not os.path.abspath(file_path).startswith(os.path.abspath(deployment_dir)):
            logger.warning(f"路径遍历攻击尝试: {filename}")
            abort(403)
        
        # 检查文件是否存在
        if os.path.isfile(file_path):
            return send_from_directory(deployment_dir, filename)
        else:
            logger.warning(f"文件不存在: {file_path}")
            abort(404)
            
    except Exception as e:
        logger.error(f"服务文件时发生错误: {e}")
        abort(500)

@app.route('/health')
def health_check():
    """健康检查"""
    return jsonify({
        'status': 'healthy',
        'timestamp': datetime.now().isoformat(),
        'files_dir': FILES_DIR
    })

@app.errorhandler(404)
def not_found(error):
    """404错误处理"""
    domain = request.headers.get('Host', '').split(':')[0]
    client_ip = request.headers.get('X-Forwarded-For', request.remote_addr)
    logger.warning(f"404错误 - 域名: {domain}, IP: {client_ip}, 路径: {request.path}")
    return "Page Not Found", 404

@app.errorhandler(500)
def internal_error(error):
    """500错误处理"""
    logger.error(f"服务器内部错误: {error}")
    return "Internal Server Error", 500

if __name__ == '__main__':
    logger.info("启动简化版蜜罐部署服务器")
    logger.info(f"文件目录: {FILES_DIR}")
    logger.info(f"配置文件: {CONFIG_FILE}")
    
    app.run(host='0.0.0.0', port=8080, debug=False)