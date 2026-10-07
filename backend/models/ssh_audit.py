"""
SQLAlchemy Model for SSH Remote Investigation & Remediation Audit Records.
Tracks all commands executed remotely via SSH with operator identity, role, target, and output.
"""
from datetime import datetime, timezone
from sqlalchemy import Column, String, Integer, Text, Boolean, DateTime
from backend.database import Base


class SSHAuditRecord(Base):
    __tablename__ = "ssh_audit_records"

    id = Column(String(64), primary_key=True, index=True)
    target_host = Column(String(128), index=True, nullable=False)
    user_email = Column(String(128), index=True, nullable=False)
    user_role = Column(String(64), nullable=False)
    command_type = Column(String(64), index=True, nullable=False)
    command_raw = Column(Text, nullable=False)
    is_containment = Column(Boolean, default=False)
    status = Column(String(32), default="SUCCESS")  # SUCCESS, FAILED, SIMULATED, BLOCKED
    exit_code = Column(Integer, default=0)
    stdout = Column(Text, nullable=True)
    stderr = Column(Text, nullable=True)
    executed_at = Column(DateTime, default=lambda: datetime.now(timezone.utc), index=True)

    def to_dict(self):
        return {
            "id": self.id,
            "target_host": self.target_host,
            "user_email": self.user_email,
            "user_role": self.user_role,
            "command_type": self.command_type,
            "command_raw": self.command_raw,
            "is_containment": self.is_containment,
            "status": self.status,
            "exit_code": self.exit_code,
            "stdout": self.stdout,
            "stderr": self.stderr,
            "executed_at": str(self.executed_at)
        }
