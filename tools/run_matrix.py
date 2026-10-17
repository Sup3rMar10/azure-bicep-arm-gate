"""Compile every fixture with the real Bicep compiler and require the gate to report EXACTLY the expected rule ids.

A missed violation fails, and so does a rule that fires on something it should not. A fixture that does not compile
is an ERROR (exit 2), never "no findings". Run: python tools/run_matrix.py
"""

from __future__ import annotations

import json
import sys
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from bicepgate import CompileError, check, compile_bicep, walk  # noqa: E402

FIXTURES = ROOT / "fixtures"


def entry_point(name: str) -> Path:
    single = next(FIXTURES.glob(f"*/{name}.bicep"), None)
    return single if single else next(FIXTURES.glob(f"*/{name}/main.bicep"))


def evaluate(name: str) -> tuple[list, list[str]]:
    template, warnings = compile_bicep(entry_point(name))
    return check(walk(template)), warnings


def run(only: list[str] | None = None) -> tuple[list[str], list[str], list[str]]:
    """Return (ok, wrong, errors), as printable lines."""
    expected = json.loads((FIXTURES / "expected.json").read_text(encoding="utf-8"))
    names = only or sorted(expected)

    def one(name: str):
        try:
            findings, _ = evaluate(name)
        except CompileError as e:
            return name, None, str(e)
        except Exception as e:  # a reader crash is "could not judge", never "no findings"
            return name, None, f"internal error: {type(e).__name__}: {e}"
        return name, sorted({f.rule for f in findings}), None

    with ThreadPoolExecutor(max_workers=8) as pool:
        results = list(pool.map(one, names))
    ok, wrong, errors = [], [], []
    for name, got, err in results:
        if err:
            errors.append(f"ERROR {name}: {err}")
        elif got == sorted(expected[name]):
            ok.append(name)
        else:
            wrong.append(f"WRONG {name}: expected {sorted(expected[name])}, got {got}")
    return ok, wrong, errors


def main() -> int:
    ok, wrong, errors = run()
    for line in errors + wrong:
        print(line)
    print(f"{len(ok)} fixtures as expected, {len(wrong)} wrong, {len(errors)} could not be judged")
    return 2 if errors else 1 if wrong else 0


if __name__ == "__main__":
    raise SystemExit(main())
