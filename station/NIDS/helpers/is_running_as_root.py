import os

def is_running_as_root() -> bool:
    """Check if the script launched by root

    Returns:
        bool: will return true if script launched by root
    """
    return os.getuid() == 0