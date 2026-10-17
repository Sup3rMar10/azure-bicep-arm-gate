"""Read a compiled ARM template into resolved resources, and be honest about what cannot be resolved.

Bicep compiles to ARM JSON in which values are often expressions: "[parameters('x')]", "[variables('tags')]",
"[resourceGroup().location]". A policy can only judge a value it can see. This module resolves the two forms that
are pure lookups (parameters and variables, through nested module deployments) and turns every other expression
into an `Unknown`, which the rules treat as "cannot verify", never as "fine". It is NOT an ARM expression engine.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any, Iterator

_PARAM = re.compile(r"^\[parameters\('([^']+)'\)\]$", re.I)
_VAR = re.compile(r"^\[variables\('([^']+)'\)\]$", re.I)


class Unknown:
    """A value that depends on something this reader cannot evaluate (a function call, a runtime value)."""

    def __init__(self, expr: str):
        self.expr = expr

    def __repr__(self) -> str:
        return f"Unknown({self.expr})"

    __hash__ = object.__hash__

    def __eq__(self, other) -> bool:  # an unknown value is never equal to anything, not even itself
        return False


class _Missing:
    def __repr__(self) -> str:
        return "MISSING"

    def __bool__(self) -> bool:
        return False


MISSING = _Missing()


def contains_unknown(value: Any) -> bool:
    if isinstance(value, Unknown):
        return True
    if isinstance(value, dict):
        return any(contains_unknown(v) for v in value.values())
    if isinstance(value, list):
        return any(contains_unknown(v) for v in value)
    return False


@dataclass
class Scope:
    params: dict[str, Any]
    variables: dict[str, Any]
    _resolving: set = field(default_factory=set)

    def resolve(self, value: Any) -> Any:
        if isinstance(value, str):
            if value.startswith("[["):  # an escaped literal "[" in ARM
                return value[1:]
            if m := _PARAM.match(value):
                return self.params.get(m.group(1).lower(), Unknown(value))
            if m := _VAR.match(value):
                name = m.group(1).lower()
                raw = {k.lower(): v for k, v in self.variables.items()}
                if name in self._resolving or name not in raw:
                    return Unknown(value)
                self._resolving.add(name)
                try:
                    return self.resolve(raw[name])
                finally:
                    self._resolving.discard(name)
            if value.startswith("[") and value.endswith("]"):
                return Unknown(value)
            return value
        if isinstance(value, dict):
            return {k: self.resolve(v) for k, v in value.items()}
        if isinstance(value, list):
            return [self.resolve(v) for v in value]
        return value


def _scope_for(template: dict, supplied: dict[str, Any]) -> Scope:
    """Parameter values for one template: what the caller supplied, else the declared default, else Unknown."""
    scope = Scope({k.lower(): v for k, v in supplied.items()}, template.get("variables", {}))
    for name, decl in template.get("parameters", {}).items():
        key = name.lower()
        if key in scope.params:
            continue
        if "defaultValue" in decl:
            scope.params[key] = scope.resolve(decl["defaultValue"])
        else:
            scope.params[key] = Unknown(f"<no value supplied for parameter '{name}'>")
    return scope


@dataclass
class Resource:
    type: str
    name: Any
    api_version: str
    body: dict  # the whole resolved resource: properties, identity, tags, kind, sku, ...
    path: str  # which module it came from, for messages

    def get(self, dotted: str) -> Any:
        """A value by dotted path (keys compare case-insensitively); MISSING if absent. Looks inside body."""
        cur: Any = self.body
        for part in dotted.split("."):
            if isinstance(cur, Unknown):
                return cur  # an unknown parent makes every child unknown
            if not isinstance(cur, dict):
                return MISSING
            found = next((k for k in cur if k.lower() == part.lower()), None)
            if found is None:
                return MISSING
            cur = cur[found]
        return cur

    @property
    def label(self) -> str:
        n = self.name if isinstance(self.name, str) else "<computed name>"
        return f"{self.type} {n}"


@dataclass
class Walk:
    resources: list[Resource] = field(default_factory=list)
    secret_params: list[tuple[str, str, str]] = field(default_factory=list)  # (path, parameter, declared type)
    opaque: list[str] = field(default_factory=list)  # deployments whose content could not be read (templateLink)


_SECRET_NAME = re.compile(r"(password|passwd|secret|token|apikey|api_key|accesskey|connectionstring|sastoken|privatekey)", re.I)


def _supplied(raw: Any, scope: Scope) -> dict[str, Any]:
    """The parameter values a module call passes in. An entry that is an expression, not {"value": ...}, is Unknown."""
    if not isinstance(raw, dict):
        return {}
    out: dict[str, Any] = {}
    for k, v in raw.items():
        if isinstance(v, dict) and "value" in v:
            out[k] = scope.resolve(v["value"])
        else:
            out[k] = Unknown(v if isinstance(v, str) else f"<parameter '{k}' comes from a reference>")
    return out


def _resources_of(template: dict) -> list[dict]:
    res = template.get("resources", [])
    return list(res.values()) if isinstance(res, dict) else list(res)  # languageVersion 2.0 keys resources by symbolic name


def walk(template: dict, params: dict[str, Any] | None = None, path: str = "main") -> Walk:
    out = Walk()
    _walk(template, _scope_for(template, params or {}), path, out)
    return out


def _walk(template: dict, scope: Scope, path: str, out: Walk) -> None:
    for pname, decl in template.get("parameters", {}).items():
        if _SECRET_NAME.search(pname) and str(decl.get("type", "")).lower() not in {"securestring", "secureobject"}:
            out.secret_params.append((path, pname, decl.get("type", "?")))
    for raw in _resources_of(template):
        condition = scope.resolve(raw["condition"]) if "condition" in raw else True
        if condition is False:
            continue  # not deployed with these parameters
        rtype = raw["type"]
        if rtype.lower() == "microsoft.resources/deployments":
            props = raw.get("properties", {})
            name = scope.resolve(raw.get("name", "?"))
            child = f"{path} > {name if isinstance(name, str) else '<module>'}"
            if "template" not in props:
                out.opaque.append(child)  # templateLink and the like: the content is somewhere else
                continue
            inner_only = props.get("expressionEvaluationOptions", {}).get("scope", "outer").lower() == "inner"
            if inner_only:
                supplied = _supplied(props.get("parameters"), scope)
                _walk(props["template"], _scope_for(props["template"], supplied), child, out)
            else:
                _walk(props["template"], scope, child, out)  # outer scope: expressions evaluate in the caller
            continue
        body = scope.resolve({k: v for k, v in raw.items() if k not in {"type", "apiVersion", "name", "dependsOn", "condition"}})
        out.resources.append(Resource(rtype, scope.resolve(raw.get("name")), raw.get("apiVersion", "?"), body, path))
