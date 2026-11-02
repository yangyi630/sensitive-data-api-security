import base64
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding
from config import settings
import os

class EncryptionService:
    def __init__(self):
        """初始化加密服务"""
        def safe_b64decode(s):
            try:
                # 确保base64字符串长度是4的倍数
                while len(s) % 4 != 0:
                    s += '='
                return base64.b64decode(s)
            except:
                # 如果解码失败，返回默认密钥
                return b'Hello World!123456789012'  # 16字节密钥
        
        # 使用默认密钥作为fallback
        current_key = settings.CURRENT_KEY or "SGVsbG8gV29ybGQ="  # "Hello World" in base64
        self.current_key = safe_b64decode(current_key)
        # 确保密钥长度为16、24或32字节
        if len(self.current_key) not in [16, 24, 32]:
            self.current_key = b'Hello World!123456789012'  # 16字节密钥
        
        self.old_keys = []
        for key in settings.OLD_KEYS:
            if key:
                decoded_key = safe_b64decode(key)
                if len(decoded_key) in [16, 24, 32]:
                    self.old_keys.append(decoded_key)
        
    def encrypt(self, plaintext: str) -> str:
        """使用当前密钥加密数据"""
        iv = os.urandom(12)  # GCM IV 长度为 12 字节
        cipher = Cipher(
            algorithms.AES(self.current_key),
            modes.GCM(iv),
            backend=default_backend()
        )
        encryptor = cipher.encryptor()
        
        # 填充明文
        padder = padding.PKCS7(128).padder()
        padded_data = padder.update(plaintext.encode('utf-8')) + padder.finalize()
        
        # 加密
        ciphertext = encryptor.update(padded_data) + encryptor.finalize()
        auth_tag = encryptor.tag
        
        # 格式: v{version}:{base64iv}:{base64authTag}:{base64ciphertext}
        return f"v0:{base64.b64encode(iv).decode('utf-8')}:{base64.b64encode(auth_tag).decode('utf-8')}:{base64.b64encode(ciphertext).decode('utf-8')}"
    
    def decrypt(self, encrypted: str) -> str:
        """解密数据，失败时尝试旧密钥"""
        try:
            parts = encrypted.split(':', 3)
            if len(parts) != 4:
                raise ValueError("无效的加密格式")
            
            version = int(parts[0][1:])  # 提取版本号
            iv = base64.b64decode(parts[1])
            auth_tag = base64.b64decode(parts[2])
            ciphertext = base64.b64decode(parts[3])
            
            # 尝试根据版本获取密钥
            if version == 0:
                key = self.current_key
            else:
                key_index = version - 1
                if key_index >= len(self.old_keys):
                    raise ValueError("未知的密钥版本")
                key = self.old_keys[key_index]
            
            # 解密
            cipher = Cipher(
                algorithms.AES(key),
                modes.GCM(iv, auth_tag),
                backend=default_backend()
            )
            decryptor = cipher.decryptor()
            padded_plaintext = decryptor.update(ciphertext) + decryptor.finalize()
            
            # 去填充
            unpadder = padding.PKCS7(128).unpadder()
            plaintext = unpadder.update(padded_plaintext) + unpadder.finalize()
            
            return plaintext.decode('utf-8')
            
        except Exception as e:
            # 尝试所有旧密钥作为回退
            for key in self.old_keys:
                try:
                    parts = encrypted.split(':', 3)
                    iv = base64.b64decode(parts[1])
                    auth_tag = base64.b64decode(parts[2])
                    ciphertext = base64.b64decode(parts[3])
                    
                    cipher = Cipher(
                        algorithms.AES(key),
                        modes.GCM(iv, auth_tag),
                        backend=default_backend()
                    )
                    decryptor = cipher.decryptor()
                    padded_plaintext = decryptor.update(ciphertext) + decryptor.finalize()
                    
                    unpadder = padding.PKCS7(128).unpadder()
                    plaintext = unpadder.update(padded_plaintext) + unpadder.finalize()
                    
                    return plaintext.decode('utf-8')
                except:
                    continue
            
            raise ValueError("解密失败")

# 创建实例
encryption_service = EncryptionService()