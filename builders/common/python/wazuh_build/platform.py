import multiprocessing
import platform


def os_id() -> str:
    name = platform.system().lower()
    if name.startswith("linux"):
        return "linux"
    if name.startswith("darwin"):
        return "macos"
    return "unknown"


def arch_id() -> str:
    mach = platform.machine().lower()
    if mach in ("x86_64", "amd64"):
        return "amd64"
    if mach in ("aarch64", "arm64"):
        return "arm64"
    return "unknown"


def cpu_count() -> int:
    try:
        return multiprocessing.cpu_count()
    except NotImplementedError:
        return 1
