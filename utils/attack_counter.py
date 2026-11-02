from datetime import datetime, timedelta
from typing import Dict
from dataclasses import dataclass, field

@dataclass
class AttackStats:
    """攻击统计数据"""
    replay_attacks: int = 0
    rate_limit_hits: int = 0
    csrf_attacks: int = 0
    invalid_tokens: int = 0
    sql_injection_attempts: int = 0
    xss_attempts: int = 0
    total_blocked: int = 0
    last_attack_time: str = None

class AttackCounter:
    """攻击拦截计数器"""

    def __init__(self):
        """初始化攻击计数器"""
        self.stats = AttackStats()
        self.stats_history = []  # 最近24小时的统计数据
        self.daily_stats = {}  # 按日期统计

    def increment_replay_attack(self):
        """增加重放攻击计数"""
        self.stats.replay_attacks += 1
        self.stats.total_blocked += 1
        self.stats.last_attack_time = datetime.now().strftime('%Y-%m-%d %H:%M:%S')

    def increment_rate_limit(self):
        """增加限流触发计数"""
        self.stats.rate_limit_hits += 1
        self.stats.total_blocked += 1
        self.stats.last_attack_time = datetime.now().strftime('%Y-%m-%d %H:%M:%S')

    def increment_csrf_attack(self):
        """增加CSRF攻击计数"""
        self.stats.csrf_attacks += 1
        self.stats.total_blocked += 1
        self.stats.last_attack_time = datetime.now().strftime('%Y-%m-%d %H:%M:%S')

    def increment_invalid_token(self):
        """增加无效令牌计数"""
        self.stats.invalid_tokens += 1
        self.stats.total_blocked += 1
        self.stats.last_attack_time = datetime.now().strftime('%Y-%m-%d %H:%M:%S')

    def get_stats(self) -> Dict:
        """获取当前统计数据"""
        return {
            "replay_attacks": self.stats.replay_attacks,
            "rate_limit_hits": self.stats.rate_limit_hits,
            "csrf_attacks": self.stats.csrf_attacks,
            "invalid_tokens": self.stats.invalid_tokens,
            "sql_injection_attempts": self.stats.sql_injection_attempts,
            "xss_attempts": self.stats.xss_attempts,
            "total_blocked": self.stats.total_blocked,
            "last_attack_time": self.stats.last_attack_time
        }

    def get_daily_stats(self, date: str = None) -> Dict:
        """获取指定日期的统计"""
        if date is None:
            date = datetime.now().strftime('%Y-%m-%d')
        return self.daily_stats.get(date, {
            "date": date,
            "replay_attacks": 0,
            "rate_limit_hits": 0,
            "csrf_attacks": 0,
            "total_blocked": 0
        })

    def record_daily_snapshot(self):
        """记录每日统计快照"""
        date = datetime.now().strftime('%Y-%m-%d')
        self.daily_stats[date] = {
            "date": date,
            "replay_attacks": self.stats.replay_attacks,
            "rate_limit_hits": self.stats.rate_limit_hits,
            "csrf_attacks": self.stats.csrf_attacks,
            "total_blocked": self.stats.total_blocked
        }

# 创建全局实例
attack_counter = AttackCounter()