"""Breach intelligence modules (HaveIBeenPwned, credential leak indicators)."""
from reconx.modules.breach.hibp import check_breaches

__all__ = ["check_breaches"]
