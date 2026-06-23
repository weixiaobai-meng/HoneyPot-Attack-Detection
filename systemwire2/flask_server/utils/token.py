import secrets
import string

# 生成随机token
def generate_random_str(length:int) -> str:
    characters = string.ascii_letters + string.digits
    token = ''.join(secrets.choice(characters) for _ in range(length))
    return token