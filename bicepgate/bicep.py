"""Compile Bicep with the real compiler. A compile error is an error, never "no resources, so no findings"."""

from __future__ import annotations

import json
import os
import shutil
import subprocess
from pathlib import Path


class CompileError(Exception):
    pass


def find_bicep() -> str:
    for candidate in (os.environ.get("BICEP"), shutil.which("bicep"), shutil.which("bicep.exe"),
                      str(Path.home() / "bin" / "bicep.exe")):
        if candidate and Path(candidate).exists():
            return candidate
    raise CompileError("the bicep CLI was not found (put it on PATH or set BICEP)")


def compile_bicep(path: str | Path) -> tuple[dict, list[str]]:
    """Return (ARM template, warnings). Raises CompileError if Bicep reports an error."""
    proc = subprocess.run([find_bicep(), "build", str(path), "--stdout"], capture_output=True, text=True, encoding="utf-8")
    lines = [ln for ln in proc.stderr.splitlines() if ln.strip()]
    if proc.returncode != 0:
        errors = [ln for ln in lines if " : Error " in ln] or lines
        raise CompileError(f"{path}: bicep build failed: " + " | ".join(errors[:3]))
    try:
        return json.loads(proc.stdout), [ln for ln in lines if " : Warning " in ln]
    except json.JSONDecodeError as e:
        raise CompileError(f"{path}: bicep produced output that is not JSON ({e})") from e
