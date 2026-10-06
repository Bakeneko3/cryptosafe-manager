"""
Compatibility shim.

The real implementation lives in src/core/audit/audit_logger.py since
Sprint 5. This module re-exports it so existing imports keep working.
"""

from src.core.audit.audit_logger import AuditLogger

__all__ = ["AuditLogger"]