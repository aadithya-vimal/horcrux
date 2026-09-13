from __future__ import annotations

import shutil
import subprocess
import time
from dataclasses import dataclass


@dataclass
class CommandResult:
    args: list[str]
    returncode: int
    stdout: str
    stderr: str
    duration: float
    installed: bool


class CommandRunner:
    def __init__(self, workspace, on_start=None, on_finish=None):
        self.workspace = workspace
        self.on_start = on_start
        self.on_finish = on_finish

    def which(self, name: str) -> str | None:
        return shutil.which(name)

    def run(self, args: list[str], artifact: str, timeout: int = 300) -> CommandResult:
        start = time.monotonic()

        if not args:
            result = CommandResult([], 127, "", "empty command", 0.0, False)
        elif not self.which(args[0]):
            result = CommandResult(
                args, 127, "", f"{args[0]}: not installed", 0.0, False
            )
        else:
            if callable(self.on_start):
                try:
                    self.on_start(args)
                except Exception:
                    pass

            try:
                proc = subprocess.run(
                    args,
                    capture_output=True,
                    text=True,
                    errors="replace",
                    timeout=timeout,
                )
                result = CommandResult(
                    args=args,
                    returncode=proc.returncode,
                    stdout=proc.stdout,
                    stderr=proc.stderr,
                    duration=time.monotonic() - start,
                    installed=True,
                )
            except subprocess.TimeoutExpired as exc:
                result = CommandResult(
                    args=args,
                    returncode=124,
                    stdout=exc.stdout or "",
                    stderr=(exc.stderr or "") + "\nTIMEOUT",
                    duration=time.monotonic() - start,
                    installed=True,
                )
            finally:
                if callable(self.on_finish):
                    try:
                        self.on_finish(args, getattr(result, "returncode", -1))
                    except Exception:
                        pass

        self.workspace.write(f"raw/{artifact}.command", " ".join(args))
        self.workspace.write(f"raw/{artifact}.stdout", result.stdout)
        self.workspace.write(f"raw/{artifact}.stderr", result.stderr)
        return result


Runner = CommandRunner
