import json

# json.dumps()方法可以把Python对象转换成JSON字符串
data = {
    "source": 0,
    "format": "word",
    "email": "123456",
    "message": "test",
    "position": "用户机器",
    "server": "external"
}

data_str = json.dumps(data,indent=2)
print()
data = json.loads(data_str)
print(data)