"""python -m bicepgate check FILE.bicep [--params FILE.json]   |   python -m bicepgate whatif FILE.json

Exit 0: nothing to fix. Exit 1: at least one error finding (a warning never fails). Exit 2: could not judge
(compile error, unreadable input), which must never look like a pass.
"""

from __future__ import annotations

import argparse
import json
import sys

from . import CompileError, WhatIfError, check, compile_bicep, evaluate, walk


def load_params(path: str | None) -> dict:
    if not path:
        return {}
    with open(path, encoding="utf-8") as f:
        doc = json.load(f)
    return {k: v["value"] for k, v in doc.get("parameters", {}).items() if "value" in v}


def report(findings) -> int:
    for f in findings:
        print(f"  {f}")
    errors = [f for f in findings if f.severity == "error"]
    print(f"{len(errors)} error(s), {len(findings) - len(errors)} warning(s)")
    return 1 if errors else 0


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(prog="bicepgate")
    sub = ap.add_subparsers(dest="cmd", required=True)
    c = sub.add_parser("check", help="compile a Bicep file with the real compiler, then apply the rules")
    c.add_argument("file")
    c.add_argument("--params", help="an ARM parameters file whose values resolve parameters with no default")
    w = sub.add_parser("whatif", help="apply the rules to a `az deployment group what-if --no-pretty-print` result")
    w.add_argument("file")
    a = ap.parse_args(argv)
    try:
        if a.cmd == "check":
            template, warnings = compile_bicep(a.file)
            for line in warnings:
                print(f"  bicep warning: {line}", file=sys.stderr)
            return report(check(walk(template, load_params(a.params))))
        with open(a.file, encoding="utf-8") as f:
            result = evaluate(json.load(f))
        print("changes: " + ", ".join(f"{k} {v}" for k, v in sorted(result.counts.items())))
        return report(result.findings)
    except (CompileError, WhatIfError, OSError, json.JSONDecodeError) as e:
        print(f"cannot judge: {e}", file=sys.stderr)
        return 2
    except Exception as e:  # an unexpected shape must exit 2, not Python's default 1, which means "findings"
        print(f"cannot judge: internal error ({type(e).__name__}: {e})", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
