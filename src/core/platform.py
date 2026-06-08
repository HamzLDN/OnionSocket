import sys


def is_windows() -> bool:
    return sys.platform == "win32"


def dashboard_available() -> bool:
    if is_windows():
        return False
    try:
        import curses  # noqa: F401

        return True
    except ImportError:
        return False
