"""Attack vector implementations for Agent Canary."""
try:
    from .files import FileWatcher, check_file_access, plant_file
    __all__ = ["plant_file", "FileWatcher", "check_file_access"]
except ImportError:
    __all__ = []
