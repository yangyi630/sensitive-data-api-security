import logging
import json
from datetime import datetime
import re

# 敏感模式脱敏
SENSITIVE_PATTERNS = [
    (r'"phone": "[^"]+"', '"phone": "***"'),
    (r'"id_card": "[^"]+"', '"id_card": "***"'),
    (r'"bank_card": "[^"]+"', '"bank_card": "***"'),
    (r'"password": "[^"]+"', '"password": "***"'),
    (r'"token": "[^"]+"', '"token": "***"'),
    (r'"refresh_token": "[^"]+"', '"refresh_token": "***"'),
    (r'1[3-9]\d{9}', '138****1234'),  # 手机号
    (r'[1-9]\d{5}(18|19|20)\d{2}((0[1-9])|(1[0-2]))(([0-2][1-9])|10|20|30|31)\d{3}[0-9Xx]', '110***********1234'),  # 身份证
    (r'\d{16,19}', '6222**********1234'),  # 银行卡
]

def mask_sensitive_data(data):
    """日志中敏感数据脱敏"""
    if isinstance(data, str):
        masked = data
        for pattern, replacement in SENSITIVE_PATTERNS:
            masked = re.sub(pattern, replacement, masked)
        return masked
    elif isinstance(data, dict):
        return {k: mask_sensitive_data(v) for k, v in data.items()}
    elif isinstance(data, list):
        return [mask_sensitive_data(item) for item in data]
    return data

class JsonFormatter(logging.Formatter):
    """结构化日志JSON格式化器"""
    def format(self, record):
        log_record = {
            "timestamp": datetime.utcnow().isoformat(),
            "level": record.levelname,
            "message": record.getMessage(),
            "module": record.module,
            "function": record.funcName,
            "line": record.lineno
        }
        
        # 添加额外数据
        if hasattr(record, "extra"):
            log_record["extra"] = mask_sensitive_data(record.extra)
        
        # 脱敏异常信息
        if record.exc_info:
            log_record["exc_info"] = str(record.exc_info[1])
        
        return json.dumps(log_record)

def setup_logger():
    """设置结构化日志"""
    logger = logging.getLogger("secure_api")
    logger.setLevel(logging.INFO)
    
    # 控制台处理器
    console_handler = logging.StreamHandler()
    console_handler.setFormatter(JsonFormatter())
    logger.addHandler(console_handler)
    
    # 文件处理器
    file_handler = logging.FileHandler("app.log")
    file_handler.setFormatter(JsonFormatter())
    logger.addHandler(file_handler)
    
    return logger

# 创建日志器实例
logger = setup_logger()