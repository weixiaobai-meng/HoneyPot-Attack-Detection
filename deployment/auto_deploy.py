"""
一键部署脚本
自动化部署蜜点系统各组件
"""

import os
import sys
import subprocess
import shutil
import json
from pathlib import Path
from datetime import datetime


class AutoDeployer:
    """自动部署器"""
    
    def __init__(self, base_dir=None):
        self.base_dir = base_dir or Path(__file__).parent.parent
        self.deployment_dir = Path(__file__).parent
        
        # 组件路径
        self.components = {
            "systemwire2": self.base_dir / "systemwire2",
            "alert_server": self.base_dir / "alert_server",
            "agent_go": self.base_dir / "agent-go",
            "ssh_vpn": self.base_dir / "ssh-vpn"
        }
    
    def check_environment(self):
        """检查部署环境"""
        print("\n" + "=" * 60)
        print("  检查部署环境")
        print("=" * 60)
        
        # 检查Python
        print("\n  [1/4] 检查Python...")
        try:
            result = subprocess.run(["python", "--version"], capture_output=True, text=True)
            print(f"    Python: {result.stdout.strip()}")
        except:
            print("    [✗] Python未安装")
            return False
        
        # 检查Go
        print("\n  [2/4] 检查Go...")
        try:
            result = subprocess.run(["go", "version"], capture_output=True, text=True)
            print(f"    Go: {result.stdout.strip()}")
        except:
            print("    [!] Go未安装 (可选)")
        
        # 检查组件
        print("\n  [3/4] 检查组件目录...")
        for name, path in self.components.items():
            exists = path.exists()
            status = "✓" if exists else "✗"
            print(f"    [{status}] {name}: {path}")
        
        # 检查SSL证书
        print("\n  [4/4] 检查SSL证书...")
        ssl_dir = self.base_dir / "systemwire2" / "agent_server" / "ssl"
        cert_files = ["server.pem", "server.key", "ca.crt"]
        for cert in cert_files:
            exists = (ssl_dir / cert).exists()
            status = "✓" if exists else "✗"
            print(f"    [{status}] {cert}")
        
        return True
    
    def install_python_deps(self):
        """安装Python依赖"""
        print("\n" + "=" * 60)
        print("  安装Python依赖")
        print("=" * 60)
        
        requirements_path = self.base_dir / "systemwire2" / "requirements.txt"
        if not requirements_path.exists():
            print("  [!] requirements.txt不存在")
            return False
        
        print("\n  正在安装依赖...")
        try:
            subprocess.run(
                ["pip", "install", "-r", str(requirements_path)],
                check=True
            )
            print("  [✓] Python依赖安装完成")
            return True
        except subprocess.CalledProcessError as e:
            print(f"  [✗] 安装失败: {e}")
            return False
    
    def init_database(self):
        """初始化数据库"""
        print("\n" + "=" * 60)
        print("  初始化数据库")
        print("=" * 60)
        
        instance_dir = self.base_dir / "systemwire2" / "instance"
        instance_dir.mkdir(exist_ok=True)
        
        db_path = instance_dir / "tripwire.db"
        if db_path.exists():
            print(f"  数据库已存在: {db_path}")
            return True
        
        print("  正在创建数据库...")
        try:
            # 导入并初始化数据库
            sys.path.insert(0, str(self.base_dir / "systemwire2"))
            from flask_server import create_app
            from flask_server.models import db
            
            app = create_app()
            with app.app_context():
                db.create_all()
            
            print(f"  [✓] 数据库已创建: {db_path}")
            return True
        except Exception as e:
            print(f"  [✗] 数据库创建失败: {e}")
            return False
    
    def build_go_components(self):
        """编译Go组件"""
        print("\n" + "=" * 60)
        print("  编译Go组件")
        print("=" * 60)
        
        go_components = [
            ("alert_server", "cmd/main.go"),
            ("agent-go", "./cmd"),
            ("ssh-vpn", ".")
        ]
        
        for name, main_path in go_components:
            component_dir = self.base_dir / name
            if not component_dir.exists():
                print(f"  [!] {name} 目录不存在，跳过")
                continue
            
            print(f"\n  编译 {name}...")
            try:
                # 检查是否有go.mod
                if not (component_dir / "go.mod").exists():
                    print(f"    [!] go.mod不存在，跳过")
                    continue
                
                subprocess.run(
                    ["go", "build", "-o", f"{name}.exe", main_path],
                    cwd=component_dir,
                    check=True,
                    capture_output=True
                )
                print(f"    [✓] {name} 编译成功")
            except subprocess.CalledProcessError as e:
                print(f"    [✗] {name} 编译失败: {e}")
            except FileNotFoundError:
                print(f"    [!] Go未安装，跳过 {name}")
        
        return True
    
    def generate_config(self):
        """生成配置文件"""
        print("\n" + "=" * 60)
        print("  生成配置文件")
        print("=" * 60)
        
        config = {
            "deployed_at": datetime.now().isoformat(),
            "components": {
                "systemwire2": {
                    "host": "0.0.0.0",
                    "port": 5001,
                    "grpc_port": 50051
                },
                "alert_server": {
                    "host": "0.0.0.0",
                    "port": 8080
                },
                "ssh_vpn": {
                    "ssh_port": 22,
                    "vpn_port": 1194
                }
            }
        }
        
        config_path = self.deployment_dir / "config" / "deployed.json"
        config_path.parent.mkdir(exist_ok=True)
        
        with open(config_path, 'w', encoding='utf-8') as f:
            json.dump(config, f, indent=2, ensure_ascii=False)
        
        print(f"  [✓] 配置已保存: {config_path}")
        return True
    
    def create_start_scripts(self):
        """创建启动脚本"""
        print("\n" + "=" * 60)
        print("  创建启动脚本")
        print("=" * 60)
        
        scripts_dir = self.deployment_dir / "scripts"
        scripts_dir.mkdir(exist_ok=True)
        
        # systemwire2启动脚本
        start_systemwire2 = f"""@echo off
echo Starting systemwire2...
cd /d "{self.base_dir / 'systemwire2'}"
python app.py
pause
"""
        with open(scripts_dir / "start_systemwire2.bat", 'w') as f:
            f.write(start_systemwire2)
        print("  [✓] start_systemwire2.bat")
        
        # alert_server启动脚本
        start_alert = f"""@echo off
echo Starting alert_server...
cd /d "{self.base_dir / 'alert_server'}"
alert_server.exe
pause
"""
        with open(scripts_dir / "start_alert_server.bat", 'w') as f:
            f.write(start_alert)
        print("  [✓] start_alert_server.bat")
        
        # ssh-vpn启动脚本
        start_ssh = f"""@echo off
echo Starting ssh-vpn...
cd /d "{self.base_dir / 'ssh-vpn'}"
ssh-auth-logger.exe
pause
"""
        with open(scripts_dir / "start_ssh_vpn.bat", 'w') as f:
            f.write(start_ssh)
        print("  [✓] start_ssh_vpn.bat")
        
        # agent-go启动脚本
        start_agent = f"""@echo off
echo Starting agent-go...
cd /d "{self.base_dir / 'agent-go'}"
agent-go.exe
pause
"""
        with open(scripts_dir / "start_agent_go.bat", 'w') as f:
            f.write(start_agent)
        print("  [✓] start_agent_go.bat")
        
        return True
    
    def deploy(self):
        """执行完整部署"""
        print("\n" + "=" * 60)
        print("  蜜点系统一键部署")
        print("=" * 60)
        
        steps = [
            ("检查环境", self.check_environment),
            ("安装Python依赖", self.install_python_deps),
            ("初始化数据库", self.init_database),
            ("编译Go组件", self.build_go_components),
            ("生成配置", self.generate_config),
            ("创建启动脚本", self.create_start_scripts)
        ]
        
        results = []
        for step_name, step_func in steps:
            try:
                success = step_func()
                results.append((step_name, success))
            except Exception as e:
                print(f"\n  [✗] {step_name} 失败: {e}")
                results.append((step_name, False))
        
        # 显示结果
        print("\n" + "=" * 60)
        print("  部署结果")
        print("=" * 60)
        
        for step_name, success in results:
            status = "✓ 成功" if success else "✗ 失败"
            print(f"  {step_name}: {status}")
        
        print("\n" + "=" * 60)
        print("  下一步操作")
        print("=" * 60)
        print("""
  1. 启动 systemwire2:
     双击 deployment/scripts/start_systemwire2.bat
     或运行: cd systemwire2 && python app.py

  2. 启动 alert_server:
     双击 deployment/scripts/start_alert_server.bat

  3. 部署 agent-go 到靶机:
     复制 agent-go/agent-go.exe 到靶机
     配置 agent-go/config/config.ini
     运行 agent-go.exe

  4. 启动 ssh-vpn:
     双击 deployment/scripts/start_ssh_vpn.bat

  5. 访问管理界面:
     http://localhost:5001
        """)
        
        return results


def main():
    import argparse
    
    parser = argparse.ArgumentParser(description="一键部署脚本")
    parser.add_argument("--check", action="store_true", help="只检查环境")
    parser.add_argument("--full", action="store_true", help="完整部署")
    
    args = parser.parse_args()
    
    deployer = AutoDeployer()
    
    if args.check:
        deployer.check_environment()
    else:
        deployer.deploy()


if __name__ == "__main__":
    main()
