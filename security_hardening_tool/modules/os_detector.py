import platform

def detect_os():
    """
    Detects the underlying operating system.
    """
    os_name = platform.system().lower()
    if os_name == "windows":
        return "windows"
    elif os_name == "linux":
        # Further detection for specific Linux distributions
        try:
            with open("/etc/os-release") as f:
                for line in f:
                    if line.startswith("ID="):
                        dist_name = line.split("=")[1].strip().replace('"', "")
                        return dist_name
        except FileNotFoundError:
            return "linux"
    return "unsupported"
