from datetime import datetime, timezone
from typing import Optional, Dict, Any
from sqlalchemy.ext.asyncio import AsyncSession
from app.models.audit_log import AuditLog
from app.core.logging import logger


async def log_audit_event(
    db: AsyncSession,
    action: str,
    target_id: Optional[str] = None,
    user_id: Optional[str] = None,
    details: Optional[Dict[str, Any]] = None,
    ip_address: Optional[str] = None
) -> None:
    """Record a structured security audit event."""
    try:
        log_entry = AuditLog(
            action=action,
            target_id=target_id,
            user_id=user_id,
            details=details or {},
            ip_address=ip_address,
            timestamp=datetime.now(timezone.utc)
        )
        db.add(log_entry)
        await db.commit()
    except Exception as e:
        logger.warning(f"Failed to record audit log ({action}): {e}")
        try:
            await db.rollback()
        except Exception:
            pass
