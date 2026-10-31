"""Wraps subprocess calls to external recon binaries with consistent
timeout/error handling so modules don't each reinvent this."""

import subprocess

from reconx.utils import logger


def run(cmd: list, timeout: int = 120) -> str:
    """
    Runs an external command, returns stdout as string.
    Returns "" (not an exception) on any failure — modules should
    treat empty output as "skip this source" rather than crash.
    """
    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
        )
        if result.returncode != 0 and not result.stdout:
            logger.warn(f"{cmd[0]} exited {result.returncode}: {result.stderr.strip()[:200]}")
        return result.stdout
    except FileNotFoundError:
        logger.warn(f"{cmd[0]} not installed — skipping this source.")
        return ""
    except subprocess.TimeoutExpired:
        logger.warn(f"{cmd[0]} timed out after {timeout}s — skipping.")
        return ""
    except Exception as e:  # pragma: no cover
        logger.warn(f"{cmd[0]} failed: {e}")
        return ""
