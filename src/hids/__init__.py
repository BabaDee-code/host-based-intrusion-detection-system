"""Host-based intrusion detection system package."""

from .auth import detect_failed_login_bursts
from .fim import hash_content, compare_baseline
from .processes import detect_suspicious_processes

__all__ = ["detect_failed_login_bursts", "hash_content", "compare_baseline", "detect_suspicious_processes"]
