import os
import shlex
import subprocess
from pathlib import Path
from typing import Iterable, Mapping, Optional, Union


Command = Union[str, Iterable[str]]


def _stringify(cmd: Command) -> str:
    if isinstance(cmd, str):
        return cmd
    return " ".join(shlex.quote(str(part)) for part in cmd)


def run(
    cmd: Command,
    *,
    cwd: Optional[Path] = None,
    env: Optional[Mapping[str, str]] = None,
    check: bool = True,
    capture: bool = False,
) -> subprocess.CompletedProcess:
    """Run a command with minimal logging."""
    cmd_list = cmd if isinstance(cmd, (list, tuple)) else cmd
    print(f"[cmd] {_stringify(cmd_list)}")
    result = subprocess.run(
        cmd,
        cwd=str(cwd) if cwd else None,
        env={**os.environ, **env} if env else None,
        shell=isinstance(cmd, str),
        check=check,
        capture_output=capture,
        text=True,
    )
    return result


def command_exists(name: str) -> bool:
    return (
        subprocess.call(
            ["which", name], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
        )
        == 0
    )
