from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.serialization import load_pem_private_key, load_pem_public_key
import os

def generate_key_pair():
    # 生成私钥
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )

    # 获取公钥
    public_key = private_key.public_key()

    # 将私钥转换为PEM格式
    private_key_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )

    # 将公钥转换为PEM格式
    public_key_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

    return private_key_pem, public_key_pem

def save_keys(private_key_pem, public_key_pem,user_name):
    private_key_filename = f"{user_name}_private_key.pem"
    with open(private_key_filename, "wb") as f:
        f.write(private_key_pem)

    public_key_filename = f"{user_name}_public_key.pem"
    with open(public_key_filename, "wb") as f:
        f.write(public_key_pem)

def key_pair(user_name):
    private_key_pem, public_key_pem = generate_key_pair()
    save_keys(private_key_pem, public_key_pem,user_name)

# if __name__ == "__main__":
#     private_key_pem, public_key_pem = generate_key_pair()
    
#     print("Public Key (PEM):")
#     print(public_key_pem.decode('utf-8'))

#     print("\nPrivate Key (PEM):")
#     print(private_key_pem.decode('utf-8'))

#     # 保存公私钥到文件
#     save_keys(private_key_pem, public_key_pem)
# key_pair('lt')