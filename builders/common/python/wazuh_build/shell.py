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
    print(f"[cmd] {_stringify(cmd)}")
    if isinstance(cmd, str):
        # String commands are trusted snippets coming from repository
        # configuration (e.g. deps.run_bash_commands). Invoke the shell
        # explicitly instead of relying on subprocess's ``shell=True``;
        # anything built from external input must be passed as an argument
        # list so it is never interpreted by a shell.
        args: Command = ["/bin/sh", "-c", cmd]
    else:
        args = cmd
    result = subprocess.run(
        args,
        cwd=str(cwd) if cwd else None,
        env={**os.environ, **env} if env else None,
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
