"""
系统启动测试脚本
用于验证系统配置和依赖是否正确
"""

import os
import sys

# 添加项目根目录到Python路径
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

def test_imports():
    """测试依赖导入"""
    print("=" * 60)
    print("  测试依赖导入")
    print("=" * 60)
    
    required_modules = [
        'flask',
        'flask_sqlalchemy',
        'flask_login',
        'flask_migrate',
        'grpc',
        'paramiko',
        'requests'
    ]
    
    missing_modules = []
    for module in required_modules:
        try:
            __import__(module)
            print(f"  [✓] {module}")
        except ImportError:
            print(f"  [✗] {module} - 未安装")
            missing_modules.append(module)
    
    if missing_modules:
        print(f"\n缺少依赖: {', '.join(missing_modules)}")
        print("请运行: pip install -r requirements.txt")
        return False
    
    print("\n所有依赖已安装!")
    return True


def test_config():
    """测试配置文件"""
    print("\n" + "=" * 60)
    print("  测试配置文件")
    print("=" * 60)
    
    try:
        import config.config as cfg
        print(f"  [✓] Flask端口: {cfg.FLASK_PORT}")
        print(f"  [✓] gRPC端口: {cfg.GRPC_PORT}")
        print(f"  [✓] 数据库类型: {cfg.DB_TYPE}")
        print(f"  [✓] TLS启用: {cfg.TLS_ENABLE}")
        return True
    except Exception as e:
        print(f"  [✗] 配置加载失败: {e}")
        return False


def test_ssl_certs():
    """测试SSL证书"""
    print("\n" + "=" * 60)
    print("  测试SSL证书")
    print("=" * 60)
    
    cert_files = [
        'agent_server/ssl/server.pem',
        'agent_server/ssl/server.key',
        'agent_server/ssl/ca.crt',
        'agent_server/ssl/client.pem',
        'agent_server/ssl/client.key'
    ]
    
    all_exist = True
    for cert_file in cert_files:
        if os.path.exists(cert_file):
            print(f"  [✓] {cert_file}")
        else:
            print(f"  [✗] {cert_file} - 不存在")
            all_exist = False
    
    return all_exist


def test_database():
    """测试数据库初始化"""
    print("\n" + "=" * 60)
    print("  测试数据库初始化")
    print("=" * 60)
    
    try:
        from flask_server import create_app
        app = create_app()
        
        with app.app_context():
            from flask_server.models import db
            db.create_all()
            print("  [✓] 数据库表创建成功")
            
            # 检查数据库文件
            db_path = os.path.join(app.instance_path, 'honeysert_live.db')
            if os.path.exists(db_path):
                print(f"  [✓] 数据库文件: {db_path}")
            else:
                print(f"  [✗] 数据库文件未创建")
                return False
        
        return True
    except Exception as e:
        print(f"  [✗] 数据库初始化失败: {e}")
        import traceback
        traceback.print_exc()
        return False


def test_flask_app():
    """测试Flask应用"""
    print("\n" + "=" * 60)
    print("  测试Flask应用")
    print("=" * 60)
    
    try:
        from flask_server import create_app
        app = create_app()
        
        # 检查路由
        with app.app_context():
            rules = [rule.rule for rule in app.url_map.iter_rules()]
            print(f"  [✓] 注册路由数量: {len(rules)}")
            
            # 检查关键路由
            key_routes = [
                '/manage/',
                '/manage/login',
                '/manage/honeypot/file',
                '/manage/honeypot/account',
                '/manage/honeypot/parasitic',
                '/manage/alert/unified',
                '/api/agent/list',
                '/api/alerts/unified'
            ]
            
            for route in key_routes:
                if route in rules:
                    print(f"  [✓] 路由存在: {route}")
                else:
                    print(f"  [?] 路由未找到: {route}")
        
        return True
    except Exception as e:
        print(f"  [✗] Flask应用测试失败: {e}")
        import traceback
        traceback.print_exc()
        return False


def test_grpc_server():
    """测试gRPC服务器"""
    print("\n" + "=" * 60)
    print("  测试gRPC服务器")
    print("=" * 60)
    
    try:
        from agent_server.server import create_grpc_server
        server = create_grpc_server()
        print("  [✓] gRPC服务器创建成功")
        print(f"  [✓] 监听端口: 50051")
        return True
    except Exception as e:
        print(f"  [✗] gRPC服务器测试失败: {e}")
        import traceback
        traceback.print_exc()
        return False


def main():
    print("\n" + "=" * 60)
    print("  蜜点管理系统 - 启动测试")
    print("=" * 60)
    
    results = []
    
    # 运行测试
    results.append(("依赖导入", test_imports()))
    results.append(("配置文件", test_config()))
    results.append(("SSL证书", test_ssl_certs()))
    results.append(("数据库", test_database()))
    results.append(("Flask应用", test_flask_app()))
    results.append(("gRPC服务器", test_grpc_server()))
    
    # 显示结果汇总
    print("\n" + "=" * 60)
    print("  测试结果汇总")
    print("=" * 60)
    
    all_passed = True
    for name, passed in results:
        status = "✓ 通过" if passed else "✗ 失败"
        print(f"  {name}: {status}")
        if not passed:
            all_passed = False
    
    print("\n" + "=" * 60)
    if all_passed:
        print("  所有测试通过! 系统可以启动。")
        print("\n  启动命令:")
        print("    python app.py")
    else:
        print("  部分测试失败，请检查上述错误。")
    print("=" * 60)
    
    return 0 if all_passed else 1


if __name__ == "__main__":
    sys.exit(main())
