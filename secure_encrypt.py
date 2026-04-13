"""
================================================================================
                        高强度文件/文件夹加密工具 (Python)
================================================================================
版本: 2.0
作者: Assistant
描述:
    本程序实现了一个能够对抗普通超算暴力破解的文件/文件夹加密工具。
    采用业界公认的强加密方案：
        - 密钥派生: Argon2id (内存硬算法，显著增加GPU/ASIC破解成本)
        - 对称加密: AES-256-GCM (提供机密性、完整性和认证)

核心安全特性:
    1. Argon2 内存硬计算: 每次加密/解密都需要消耗大量内存(默认512MB)，
       使得攻击者无法使用低成本硬件进行大规模并行破解。
    2. AES-256-GCM 认证加密: 不仅加密数据，还能检测任何篡改，防止密文被修改。
    3. 随机盐值: 每个加密文件使用独立的16字节随机盐，阻止彩虹表攻击。
    4. 随机Nonce: 每次加密使用独立的12字节随机数，保证相同明文每次加密结果不同。

功能列表:
    - 加密单个文件
    - 解密单个文件
    - 加密整个文件夹 (自动打包为ZIP后加密)

使用前提:
    - Python 3.7+
    - 安装依赖库: pip install argon2-cffi pycryptodome

用法示例:
    python secure_encrypt.py
    然后根据交互提示选择操作并输入密码和路径。

安全警告:
    - 请务必牢记您的密码！密码丢失后数据将永久无法恢复。
    - 建议将密码保存在安全的离线密码管理器中。
    - 本工具仅用于合法用途，用户需遵守当地法律法规。

================================================================================
"""

import os
import sys
import shutil
import tempfile
import getpass
import secrets
import hashlib
from base64 import b64encode, b64decode
from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError, VerificationError
from Crypto.Cipher import AES

# --- 配置参数 (可根据安全需求调整) ---
# AES-256 密钥长度 (32字节 = 256位)
KEY_LENGTH = 32
# Argon2 参数 (增大可提高安全性，但会减慢加密/解密速度)
ARGON2_TIME_COST = 4          # 迭代次数
ARGON2_MEMORY_COST = 512 * 1024 # 内存成本 (512 MB)，关键抗破解参数
ARGON2_PARALLELISM = 2        # 并行度
ARGON2_HASH_LEN = 32          # 输出哈希长度
ARGON2_SALT_LEN = 16          # 盐值长度

# 初始化 Argon2 PasswordHasher
ph = PasswordHasher(
    time_cost=ARGON2_TIME_COST,
    memory_cost=ARGON2_MEMORY_COST,
    parallelism=ARGON2_PARALLELISM,
    hash_len=ARGON2_HASH_LEN,
    salt_len=ARGON2_SALT_LEN
)

# --- 密钥派生函数 (核心抗暴力破解环节) ---
def derive_key_from_password(password: str, salt: bytes = None) -> tuple[bytes, bytes]:
    """
    使用Argon2id从用户密码派生一个安全的AES-256密钥。
    
    参数:
        password: 用户输入的密码字符串
        salt:     盐值(bytes)，如果为None则生成新的随机盐
    
    返回:
        (derived_key, salt): 派生出的32字节密钥和使用的盐值
    """
    if salt is None:
        salt = secrets.token_bytes(ARGON2_SALT_LEN)
    
    password_bytes = password.encode('utf-8')
    
    # Argon2 哈希计算 (此步骤内存和时间开销较大，是防破解的关键)
    derived_hash = ph.hash(password_bytes, salt=salt)
    
    # 将Argon2输出的哈希字符串进行SHA256二次哈希，确保密钥长度为32字节
    aes_key = hashlib.sha256(derived_hash.encode('utf-8')).digest()
    
    return aes_key, salt

# --- AES-256-GCM 加密与解密 ---
def encrypt_data(data: bytes, password: str) -> bytes:
    """
    使用AES-256-GCM加密数据。
    
    加密后数据结构:
        salt (16B) + nonce (12B) + tag (16B) + ciphertext
    
    返回:
        完整的加密数据块(bytes)
    """
    salt = secrets.token_bytes(ARGON2_SALT_LEN)
    key, _ = derive_key_from_password(password, salt)
    
    nonce = secrets.token_bytes(12)  # GCM推荐12字节
    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
    
    ciphertext, tag = cipher.encrypt_and_digest(data)
    
    # 拼接所有必要信息
    return salt + nonce + tag + ciphertext

def decrypt_data(encrypted_blob: bytes, password: str) -> bytes:
    """
    解密由 encrypt_data 生成的数据块。
    
    参数:
        encrypted_blob: 包含salt+nonce+tag+ciphertext的加密数据
        password:       解密密码
    
    返回:
        解密后的原始数据(bytes)
    
    异常:
        ValueError: 密码错误或数据损坏时抛出
    """
    if len(encrypted_blob) < ARGON2_SALT_LEN + 12 + 16:
        raise ValueError("加密数据格式无效或已损坏")
    
    salt = encrypted_blob[:ARGON2_SALT_LEN]
    nonce = encrypted_blob[ARGON2_SALT_LEN:ARGON2_SALT_LEN+12]
    tag = encrypted_blob[ARGON2_SALT_LEN+12:ARGON2_SALT_LEN+12+16]
    ciphertext = encrypted_blob[ARGON2_SALT_LEN+12+16:]
    
    key, _ = derive_key_from_password(password, salt)
    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
    
    try:
        plaintext = cipher.decrypt_and_verify(ciphertext, tag)
        return plaintext
    except ValueError as e:
        raise ValueError("解密失败：密码错误或数据已被篡改。") from e

# --- 文件操作辅助函数 ---
def encrypt_file(filepath: str, password: str, output_path: str = None) -> str:
    """
    加密单个文件。
    
    返回:
        加密后文件的保存路径
    """
    with open(filepath, 'rb') as f:
        data = f.read()
    
    encrypted_data = encrypt_data(data, password)
    
    if output_path is None:
        output_path = filepath + '.enc'
    
    with open(output_path, 'wb') as f:
        f.write(encrypted_data)
    
    return output_path

def decrypt_file(filepath: str, password: str, output_path: str = None) -> str:
    """
    解密单个文件。若解密后数据是ZIP压缩包，会提示用户是否解压为文件夹。
    
    返回:
        解密后文件/文件夹的保存路径
    """
    with open(filepath, 'rb') as f:
        encrypted_data = f.read()
    
    decrypted_data = decrypt_data(encrypted_data, password)
    
    # 如果没有指定输出路径，智能生成
    if output_path is None:
        if filepath.endswith('.enc'):
            base = filepath[:-4]
        else:
            base = filepath + '.dec'
        output_path = base
    
    # 写入解密数据
    with open(output_path, 'wb') as f:
        f.write(decrypted_data)
    
    # 检查是否为ZIP文件 (文件夹加密时打包的格式)
    if decrypted_data[:2] == b'PK':
        print(f"检测到解密后的文件是ZIP压缩包: {output_path}")
        ans = input("是否将其解压为文件夹？(y/n): ").strip().lower()
        if ans == 'y':
            extract_dir = input("请输入解压目标文件夹路径 (直接回车使用原文件名): ").strip()
            if not extract_dir:
                extract_dir = os.path.splitext(output_path)[0]
            # 解压ZIP
            import zipfile
            with zipfile.ZipFile(output_path, 'r') as zf:
                zf.extractall(extract_dir)
            print(f"已解压至文件夹: {extract_dir}")
            # 可选：删除临时ZIP文件
            del_zip = input("是否删除解密出的ZIP文件？(y/n): ").strip().lower()
            if del_zip == 'y':
                os.remove(output_path)
                print(f"已删除: {output_path}")
            return extract_dir
    
    return output_path

def encrypt_folder(folder_path: str, password: str, output_path: str = None) -> str:
    """
    加密整个文件夹：先打包为ZIP，再加密该ZIP文件。
    
    参数:
        folder_path: 要加密的文件夹路径
        password:    加密密码
        output_path: 加密后文件的保存路径，默认在文件夹同级目录生成 [文件夹名].zip.enc
    
    返回:
        加密后文件的保存路径
    """
    if not os.path.isdir(folder_path):
        raise ValueError(f"路径不是文件夹: {folder_path}")
    
    folder_name = os.path.basename(os.path.normpath(folder_path))
    
    # 在临时目录创建ZIP压缩包
    with tempfile.TemporaryDirectory() as tmpdir:
        zip_basename = folder_name
        zip_path = os.path.join(tmpdir, zip_basename)
        # shutil.make_archive 会自动添加后缀，我们传入不含后缀的路径
        created_zip = shutil.make_archive(zip_path, 'zip', folder_path)
        
        # 读取ZIP文件内容
        with open(created_zip, 'rb') as f:
            zip_data = f.read()
    
    # 加密ZIP数据
    encrypted_data = encrypt_data(zip_data, password)
    
    if output_path is None:
        output_path = os.path.join(os.path.dirname(folder_path), folder_name + '.zip.enc')
    
    with open(output_path, 'wb') as f:
        f.write(encrypted_data)
    
    return output_path

# --- 命令行交互主程序 ---
def main():
    print("=" * 70)
    print("          高强度文件/文件夹加密工具 (Argon2 + AES-256-GCM)")
    print("=" * 70)
    print("请选择操作:")
    print("  1. 加密单个文件")
    print("  2. 解密文件 (自动识别并解压文件夹)")
    print("  3. 加密整个文件夹 (自动打包为ZIP)")
    print("=" * 70)
    
    choice = input("请输入选项 (1/2/3): ").strip()
    
    # --- 加密文件 ---
    if choice == '1':
        filepath = input("请输入要加密的文件路径: ").strip()
        if not os.path.isfile(filepath):
            print(f"错误: 文件不存在 - {filepath}")
            sys.exit(1)
        
        password = getpass.getpass("请输入加密密码: ")
        password_confirm = getpass.getpass("请再次输入加密密码: ")
        if password != password_confirm:
            print("错误: 两次输入的密码不一致。")
            sys.exit(1)
        
        output = input("加密后文件保存路径 (直接回车添加.enc后缀): ").strip()
        if not output:
            output = None
        
        try:
            result = encrypt_file(filepath, password, output)
            print(f"\n✅ 文件加密成功！保存至: {result}")
        except Exception as e:
            print(f"\n❌ 加密失败: {e}")
            sys.exit(1)
    
    # --- 解密文件 ---
    elif choice == '2':
        filepath = input("请输入要解密的文件路径: ").strip()
        if not os.path.isfile(filepath):
            print(f"错误: 文件不存在 - {filepath}")
            sys.exit(1)
        
        password = getpass.getpass("请输入解密密码: ")
        
        output = input("解密后文件保存路径 (直接回车自动处理): ").strip()
        if not output:
            output = None
        
        try:
            result = decrypt_file(filepath, password, output)
            print(f"\n✅ 解密成功！结果位于: {result}")
        except ValueError as e:
            print(f"\n❌ 解密失败: {e}")
            sys.exit(1)
        except Exception as e:
            print(f"\n❌ 发生未知错误: {e}")
            sys.exit(1)
    
    # --- 加密文件夹 ---
    elif choice == '3':
        folderpath = input("请输入要加密的文件夹路径: ").strip()
        if not os.path.isdir(folderpath):
            print(f"错误: 文件夹不存在 - {folderpath}")
            sys.exit(1)
        
        password = getpass.getpass("请输入加密密码: ")
        password_confirm = getpass.getpass("请再次输入加密密码: ")
        if password != password_confirm:
            print("错误: 两次输入的密码不一致。")
            sys.exit(1)
        
        output = input("加密后文件保存路径 (直接回车生成 [文件夹名].zip.enc): ").strip()
        if not output:
            output = None
        
        try:
            result = encrypt_folder(folderpath, password, output)
            print(f"\n✅ 文件夹加密成功！保存至: {result}")
        except Exception as e:
            print(f"\n❌ 加密失败: {e}")
            sys.exit(1)
    
    else:
        print("无效选项，请输入 1、2 或 3。")
        sys.exit(1)

if __name__ == "__main__":
    main()
