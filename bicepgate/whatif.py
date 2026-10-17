"""Gate on the result of `az deployment group what-if --no-pretty-print`, before anything is deployed.

What-if has already resolved every expression, so the `after` of a change is a concrete resource and the SAME rules
that run on the compiled template can run on it, with nothing left unknown. On top of that, deletes of data stores
are blocked, and a change to a resource that was already non-compliant only warns (it does not block an unrelated
edit), while a change that introduces a violation fails.

The input shape (changes[].changeType / resourceId / before / after) is what I understand the Azure CLI to emit;
the fixtures are written by hand to that shape and NO real what-if produced them. A document that does not look
like it raises WhatIfError, which the command line turns into exit 2.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from .arm import Resource
from .rules import BY_TYPE, Finding, check_resource

CHANGE_TYPES = {"Create", "Delete", "Ignore", "Deploy", "NoChange", "Modify"}
# Deleting these loses data or identity that cannot be recreated by deploying again.
PROTECTED = {"microsoft.keyvault/vaults", "microsoft.storage/storageaccounts", "microsoft.sql/servers",
             "microsoft.sql/servers/databases", "microsoft.dbforpostgresql/flexibleservers",
             "microsoft.documentdb/databaseaccounts", "microsoft.recoveryservices/vaults"}


class WhatIfError(Exception):
    pass


def type_of(resource_id: str) -> str:
    """microsoft.storage/storageaccounts from /subscriptions/.../providers/Microsoft.Storage/storageAccounts/x."""
    parts = resource_id.split("/providers/")
    if len(parts) < 2:
        raise WhatIfError(f"not a resource id: {resource_id!r}")
    segs = [s for s in parts[-1].split("/") if s]
    if len(segs) < 3:
        raise WhatIfError(f"not a resource id: {resource_id!r}")
    namespace, rest = segs[0], segs[1:]
    if len(rest) % 2:
        raise WhatIfError(f"not a resource id: {resource_id!r}")
    return "/".join([namespace] + rest[0::2]).lower()


@dataclass
class Result:
    findings: list[Finding] = field(default_factory=list)
    counts: dict[str, int] = field(default_factory=dict)


def _as_resource(change: dict, which: str, rtype: str) -> Resource:
    body = change.get(which)
    if not isinstance(body, dict):
        raise WhatIfError(f"{change.get('resourceId')}: a {change.get('changeType')} change has no {which!r} object")
    shown = body.get("type") if isinstance(body.get("type"), str) else rtype
    return Resource(shown, body.get("name", "?"), body.get("apiVersion", "?"), body, "what-if")


def evaluate(doc: dict) -> Result:
    if not isinstance(doc, dict) or not isinstance(doc.get("changes"), list):
        raise WhatIfError("not a what-if result: there is no 'changes' list")
    if doc.get("error"):
        raise WhatIfError(f"what-if itself reported an error: {doc['error']}")
    if str(doc.get("status", "")).lower() != "succeeded":
        raise WhatIfError(f"what-if status is {doc.get('status')!r}, not Succeeded")
    res = Result()
    for change in doc["changes"]:
        ct, rid = change.get("changeType") if isinstance(change, dict) else None, change.get("resourceId") if isinstance(change, dict) else None
        if ct not in CHANGE_TYPES:
            raise WhatIfError(f"unknown changeType {ct!r} for {rid!r}")
        if not isinstance(rid, str):
            raise WhatIfError("a change has no resourceId")
        res.counts[ct] = res.counts.get(ct, 0) + 1
        rtype = type_of(rid)
        label = f"{rtype} {rid.rsplit('/', 1)[-1]}"
        if ct == "Delete":
            if rtype in PROTECTED:
                res.findings.append(Finding("WI-001", "error", label, "this change deletes a data store or vault; do it deliberately, outside the pipeline"))
            else:
                res.findings.append(Finding("WI-002", "warn", label, "this change deletes a resource"))
        elif ct == "Ignore":
            res.findings.append(Finding("WI-003", "warn", label, "what-if did not evaluate this resource, so it is not checked"))
        elif ct in {"Create", "Modify"}:
            after = check_resource(_as_resource(change, "after", rtype))
            before_rules = set()
            if ct == "Modify" and isinstance(change.get("before"), dict):
                before_rules = {f.rule for f in check_resource(_as_resource(change, "before", rtype))}
            for f in after:
                if f.rule in before_rules and f.severity == "error":
                    f = Finding(f.rule, "warn", f.resource, f.message + " (already the case before this change)", f.unverifiable)
                res.findings.append(f)
            if rtype not in BY_TYPE:
                res.findings.append(Finding("COV-002", "warn", label, "a type these rules do not cover"))
    return res
