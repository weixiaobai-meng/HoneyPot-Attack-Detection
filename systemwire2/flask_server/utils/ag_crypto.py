import hashlib
from base64 import urlsafe_b64encode, urlsafe_b64decode
import json
import logging

import requests

OK = 0
ERROR = 1

def generate_key(client_id, hostname):
    key_str = client_id + hostname
    key = hashlib.sha256(key_str.encode()).digest()
    return key

def encrypt_data(data, key):
    try:
        # XOR加密
        data_byte = data.encode()
        encrypted_data = bytearray()
        for i in range(len(data)):
            encrypted_data.append(data_byte[i] ^ key[i % len(key)])
        return OK,urlsafe_b64encode(encrypted_data).decode()
    except Exception as e:
        return ERROR, str(e)

def decrypt_data(encrypted_data, key):
    try:
        encrypted_data = urlsafe_b64decode(encrypted_data)
        decrypted_data = bytearray()
        for i in range(len(encrypted_data)):
            decrypted_data.append(encrypted_data[i] ^ key[i % len(key)])
        return OK,decrypted_data.decode()
    except Exception as e:
        return ERROR,e

if __name__ == "__main__":
    # logging.basicConfig(level=logging.INFO)
    
    # client_id = "client_id"
    # hostname = "hostname"
    # key = generate_key(client_id, hostname)
    # logging.info(f"密钥: {key}")
    
    # data = {
    #     "command": "add_dirs",
    #     "args": "/home/cly/test,/home/cly/test2"
    # }
    # # 转换为字符串
    # data_str = json.dumps(data)
    
    # err,en_info = encrypt_data(data_str, key)
    # if err:
    #     logging.info(f"Encrypted error: {en_info}")
        
    # logging.info(f"加密后的数据: {en_info}")
    
    # err,de_info = decrypt_data(en_info, key)
    # if err:
    #     logging.info(f"Encrypted error: {en_info}")
        
    # logging.info(f"解密后的数据: {de_info}")
    
    # # 解析数据
    # try:
    #     data = json.loads(de_info)
    #     logging.info(f"Parsed data: {data}")
    # except json.JSONDecodeError as e:
    #     logging.info(f"JSON解析错误: {e}")
  
  
    # 测试心跳，接收命令
    url = "http://localhost:5001/agent/beat"
    data1 = {
        'client_id': "abc",
        'hostname' : "testpc",
        'ope_sys' : "windows 11",
        'status': "online",
    }
    response = requests.get(url, params=data1)
    print(response.json().get("message"))
    encoded_data = response.json().get("data")
    key = generate_key("abc","testpc")
    res,decoded_data = decrypt_data(encoded_data, key)
    print(decoded_data)
    
    # 测试加密传输告警
    data2 = {
        'count': 2,
        'data': [{
                "time":"Wed Jul 03 14:33:06 2024",
                "PROCTITL":{"ASD5G":"WGF"},
                "CWD":{"ASD5G":"WGF"},
                "SYSCALL":{"ASD5G":"WGF"},
                "PATH":{"ASD5G":"WGF"}
            },
        ]
    }
    key = generate_key("abc","testpc")
    res,data_en = encrypt_data(json.dumps(data2), key)
    # print(res)
    print("加密:",data_en)
    
    data2_report = {
        'client_id': "abc",
        'data':data_en
    }
    # url2 = "http://localhost:5001/agent/report"
    # response = requests.post(url2, json=data2_report)
    # print(response.text)
    res,decoded_data = decrypt_data(data2_report.get("data"), key)
    print(decoded_data)
    