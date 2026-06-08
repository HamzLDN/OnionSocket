from . import client, server

__all__ = ["client", "server", "directory"]


def __getattr__(name):
    if name == "directory":
        from .server import directory

        return directory
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
