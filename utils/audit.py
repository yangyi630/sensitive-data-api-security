from sqlalchemy.ext.asyncio import AsyncSession
from models import AuditLog
from datetime import datetime

async def log_audit(
    db: AsyncSession,
    user_id: int,
    action: str,
    resource: str,
    ip_address: str,
    result: str,
    details: str = None
):
    """记录审计事件"""
    audit_log = AuditLog(
        user_id=user_id,
        action=action,
        resource=resource,
        ip_address=ip_address,
        result=result,
        details=details
    )
    
    db.add(audit_log)
    await db.commit()

async def get_recent_audit_logs(
    db: AsyncSession,
    limit: int = 20
) -> list[AuditLog]:
    """获取最近的审计日志"""
    from sqlalchemy import select
    from sqlalchemy import desc
    
    result = await db.execute(
        select(AuditLog)
        .order_by(desc(AuditLog.created_at))
        .limit(limit)
    )
    
    return result.scalars().all()