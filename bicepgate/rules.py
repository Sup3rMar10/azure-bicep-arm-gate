"""The rules. Each one reads a resolved resource and says: fine, violated, or cannot verify.

Design decisions, on purpose:
  * A security property must be SET EXPLICITLY. Service defaults change between API versions and a reviewer cannot
    see a default in the diff, so "absent" is a violation, with one exception noted in the rule.
  * A value this reader cannot resolve (an expression it does not evaluate) is reported as UNVERIFIABLE and fails
    the gate like a violation. A gate that passes what it could not read is not a gate.
"""

from __future__ import annotations

import ipaddress
from dataclasses import dataclass
from typing import Callable, Iterable

from .arm import MISSING, Resource, Unknown, Walk, contains_unknown

STORAGE = "microsoft.storage/storageaccounts"
VAULT = "microsoft.keyvault/vaults"
NSG = "microsoft.network/networksecuritygroups"
NSG_RULE = "microsoft.network/networksecuritygroups/securityrules"
SITE = "microsoft.web/sites"
SLOT = "microsoft.web/sites/slots"
TAGGED = {STORAGE, VAULT, NSG, SITE}


@dataclass(frozen=True)
class Finding:
    rule: str
    severity: str  # "error" fails the gate, "warn" only prints
    resource: str
    message: str
    unverifiable: bool = False

    def __str__(self) -> str:
        flag = " (cannot verify)" if self.unverifiable else ""
        return f"[{self.severity}] {self.rule}{flag}: {self.resource}: {self.message}"


def _unverifiable(rule: str, severity: str, r: Resource, what: str, value) -> Finding:
    shown = value.expr if isinstance(value, Unknown) else "a value that depends on an expression"
    return Finding(rule, severity, r.label, f"{what} cannot be verified: it is {shown}", True)


def expect(r: Resource, rule: str, path: str, ok: Callable, want: str, severity: str = "error") -> list[Finding]:
    v = r.get(path)
    if contains_unknown(v):
        return [_unverifiable(rule, severity, r, path, v)]
    if v is MISSING:
        return [Finding(rule, severity, r.label, f"{path} is not set; set it explicitly to {want}")]
    if not ok(v):
        return [Finding(rule, severity, r.label, f"{path} is {v!r}; it must be {want}")]
    return []


def _in(*allowed):
    return lambda v: isinstance(v, str) and v in allowed


def _is(expected):
    return lambda v: v is expected


def exposure(r: Resource, rule: str, base: str = "properties") -> list[Finding]:
    """Reachable only privately: public network access disabled, or the firewall's default action is Deny."""
    pna, acl = r.get(f"{base}.publicNetworkAccess"), r.get(f"{base}.networkAcls.defaultAction")
    if (isinstance(pna, str) and pna.lower() == "disabled") or (isinstance(acl, str) and acl.lower() == "deny"):
        return []
    for v in (pna, acl):
        if contains_unknown(v):
            return [_unverifiable(rule, "error", r, "public network access", v)]
    return [Finding(rule, "error", r.label, f"it is reachable from the internet: publicNetworkAccess is {pna!r} and "
                                              f"networkAcls.defaultAction is {acl!r}; disable public access or set the default action to Deny")]


# --- storage -------------------------------------------------------------------------------------------------

def storage(r: Resource) -> Iterable[Finding]:
    yield from expect(r, "STG-001", "properties.supportsHttpsTrafficOnly", _is(True), "true")
    yield from expect(r, "STG-002", "properties.minimumTlsVersion", _in("TLS1_2", "TLS1_3"), "TLS1_2 or TLS1_3")
    yield from expect(r, "STG-003", "properties.allowBlobPublicAccess", _is(False), "false")
    yield from exposure(r, "STG-004")
    yield from expect(r, "STG-005", "properties.allowSharedKeyAccess", _is(False), "false (use Entra ID instead of account keys)", "warn")


# --- key vault -----------------------------------------------------------------------------------------------

def vault(r: Resource) -> Iterable[Finding]:
    yield from expect(r, "KV-001", "properties.enablePurgeProtection", _is(True), "true")
    yield from expect(r, "KV-002", "properties.enableRbacAuthorization", _is(True), "true (not access policies)")
    # Soft delete is on by default and cannot be switched off on a new vault, so absent is fine; present must be sane.
    soft, days = r.get("properties.enableSoftDelete"), r.get("properties.softDeleteRetentionInDays")
    for v, what in ((soft, "properties.enableSoftDelete"), (days, "properties.softDeleteRetentionInDays")):
        if contains_unknown(v):
            yield _unverifiable("KV-003", "error", r, what, v)
    if soft is False:
        yield Finding("KV-003", "error", r.label, "properties.enableSoftDelete is false")
    if isinstance(days, int) and not isinstance(days, bool) and days < 30:
        yield Finding("KV-003", "error", r.label, f"properties.softDeleteRetentionInDays is {days}; keep at least 30")
    yield from exposure(r, "KV-004")


# --- network security groups ---------------------------------------------------------------------------------
# Tri-state logic: True, False, or None for "cannot tell". The rule fires on all-True, is quiet if anything is
# False, and is "cannot verify" otherwise.

def _any(values: list) -> bool | None:
    if any(v is True for v in values):
        return True
    return None if any(v is None for v in values) else False


def _all(values: list) -> bool | None:
    if any(v is False for v in values):
        return False
    return None if any(v is None for v in values) else True


def source_is_open(prefix) -> bool | None:
    if isinstance(prefix, Unknown) or not isinstance(prefix, str):
        return None
    p = prefix.strip().lower()
    if p in {"*", "any", "internet"}:
        return True
    try:
        return ipaddress.ip_network(p, strict=False).prefixlen == 0
    except ValueError:
        return False  # a service tag such as VirtualNetwork, or a named range


def port_range(spec) -> tuple[int, int] | None:
    if not isinstance(spec, str):
        return None
    s = spec.strip()
    if s == "*":
        return 0, 65535
    try:
        lo, dash, hi = s.partition("-")
        low, high = (int(lo), int(hi)) if dash else (int(lo), int(lo))
    except ValueError:
        return None
    return (low, high) if 0 <= low <= high <= 65535 else None  # a reversed or out-of-range spec is not a range


def covers(specs: list, ports: list[int]) -> bool | None:
    """Does any spec include any of the ports (inclusive at both ends)?"""
    results = []
    for spec in specs:
        rng = port_range(spec)
        results.append(None if rng is None else any(rng[0] <= p <= rng[1] for p in ports))
    return _any(results)


def _listed(props: dict, single: str, many: str) -> list | Unknown:
    out = []
    for key, is_list in ((single, False), (many, True)):
        v = next((props[k] for k in props if k.lower() == key.lower()), MISSING)
        if isinstance(v, Unknown):
            return v
        if v is MISSING:
            continue
        out.extend(v if is_list and isinstance(v, list) else [v])
    return out


def _tri_eq(v, want: str) -> bool | None:
    if isinstance(v, Unknown) or v is MISSING:
        return None
    return isinstance(v, str) and v.lower() == want


def _nsg_findings(r: Resource, props: dict) -> Iterable[Finding]:
    get = lambda k: next((props[x] for x in props if x.lower() == k.lower()), MISSING)  # noqa: E731
    applies = _all([_tri_eq(get("direction"), "inbound"), _tri_eq(get("access"), "allow")])
    if applies is False:
        return
    sources = _listed(props, "sourceAddressPrefix", "sourceAddressPrefixes")
    dports = _listed(props, "destinationPortRange", "destinationPortRanges")
    src = None if isinstance(sources, Unknown) else _any([source_is_open(s) for s in sources])
    name = get("name") if isinstance(get("name"), str) else "?"
    for rule, what in (("NSG-001", "SSH (22) or RDP (3389)"), ("NSG-002", "every port")):
        if isinstance(dports, Unknown):
            hit = None
        elif rule == "NSG-001":
            hit = covers(dports, [22, 3389])
        else:
            hit = _any([None if port_range(s) is None else port_range(s) == (0, 65535) for s in dports])
        verdict = _all([applies, src, hit])
        if verdict is True:
            yield Finding(rule, "error", r.label, f"rule {name!r} allows inbound traffic from any source to {what}")
        elif verdict is None:
            yield Finding(rule, "error", r.label, f"rule {name!r} cannot be verified: it may allow inbound traffic from any "
                                                  f"source to {what}, but a value it depends on is an expression", True)


def nsg(r: Resource) -> Iterable[Finding]:
    rules = r.get("properties.securityRules")
    if isinstance(rules, Unknown):
        yield _unverifiable("NSG-001", "error", r, "properties.securityRules", rules)
        return
    for item in rules if isinstance(rules, list) else []:
        if isinstance(item, dict):
            props = item.get("properties")
            yield from _nsg_findings(r, {"name": item.get("name", "?"), **(props if isinstance(props, dict) else {})})


def nsg_rule(r: Resource) -> Iterable[Finding]:
    props = r.get("properties")
    if isinstance(props, dict):
        yield from _nsg_findings(r, {"name": r.name if isinstance(r.name, str) else "?", **props})


# --- app service -----------------------------------------------------------------------------------------------

def site(r: Resource) -> Iterable[Finding]:
    yield from expect(r, "WEB-001", "properties.httpsOnly", _is(True), "true")
    yield from expect(r, "WEB-002", "properties.siteConfig.minTlsVersion", _in("1.2", "1.3"), "1.2 or 1.3")
    yield from expect(r, "WEB-003", "properties.siteConfig.ftpsState", _in("Disabled", "FtpsOnly"), "Disabled or FtpsOnly")
    ident = r.get("identity.type")
    if contains_unknown(ident):
        yield _unverifiable("WEB-004", "warn", r, "identity.type", ident)
    elif not (isinstance(ident, str) and ("SystemAssigned" in ident or "UserAssigned" in ident)):
        yield Finding("WEB-004", "warn", r.label, "no managed identity; use one instead of stored credentials")
    debug = r.get("properties.siteConfig.remoteDebuggingEnabled")
    if contains_unknown(debug):
        yield _unverifiable("WEB-005", "error", r, "properties.siteConfig.remoteDebuggingEnabled", debug)
    elif debug is True:
        yield Finding("WEB-005", "error", r.label, "properties.siteConfig.remoteDebuggingEnabled is true")


# --- tags --------------------------------------------------------------------------------------------------------

REQUIRED_TAGS = ("owner", "env")


def tags(r: Resource) -> Iterable[Finding]:
    v = r.get("tags")
    if contains_unknown(v):
        yield _unverifiable("TAG-001", "error", r, "tags", v)
        return
    if not isinstance(v, dict):
        yield Finding("TAG-001", "error", r.label, f"it has no tags; {', '.join(REQUIRED_TAGS)} are required")
        return
    for key in REQUIRED_TAGS:
        val = next((x for k, x in v.items() if k.lower() == key), MISSING)
        if contains_unknown(val):
            yield _unverifiable("TAG-001", "error", r, f"tag {key}", val)
        elif not (isinstance(val, str) and val.strip()):
            yield Finding("TAG-001", "error", r.label, f"tag {key!r} is missing or empty")


BY_TYPE: dict[str, list[Callable[[Resource], Iterable[Finding]]]] = {
    STORAGE: [storage], VAULT: [vault], NSG: [nsg], NSG_RULE: [nsg_rule], SITE: [site], SLOT: [site],
}

RULES = {  # every rule id and what it says; a test requires each to be exercised by a failing fixture
    "STG-001": "storage account allows plain HTTP", "STG-002": "storage minimum TLS below 1.2",
    "STG-003": "storage allows anonymous blob access", "STG-004": "storage reachable from the internet",
    "STG-005": "storage shared key access enabled (warning)",
    "KV-001": "key vault without purge protection", "KV-002": "key vault uses access policies, not RBAC",
    "KV-003": "key vault soft delete off or retention under 30 days", "KV-004": "key vault reachable from the internet",
    "NSG-001": "inbound SSH/RDP from any source", "NSG-002": "inbound every port from any source",
    "WEB-001": "web app allows plain HTTP", "WEB-002": "web app minimum TLS below 1.2",
    "WEB-003": "web app FTP allowed", "WEB-004": "web app has no managed identity (warning)",
    "WEB-005": "web app remote debugging on",
    "TAG-001": "missing owner or env tag", "SEC-001": "secret-looking parameter is not securestring",
    "COV-001": "a deployment's content cannot be read", "COV-002": "no rules for this resource type (warning)",
}


def check_resource(r: Resource) -> list[Finding]:
    out: list[Finding] = []
    for fn in BY_TYPE.get(r.type.lower(), []):
        out.extend(fn(r))
    if r.type.lower() in TAGGED:
        out.extend(tags(r))
    return out


def check(w: Walk) -> list[Finding]:
    out: list[Finding] = []
    for path, name, typ in w.secret_params:
        out.append(Finding("SEC-001", "error", f"parameter {name} ({path})", f"its name looks like a secret but its type is {typ}; use securestring"))
    for path in w.opaque:
        out.append(Finding("COV-001", "error", path, "its template is not inline (a templateLink?), so nothing in it was checked", True))
    unchecked: dict[str, int] = {}
    for r in w.resources:
        out.extend(check_resource(r))
        if r.type.lower() not in BY_TYPE and r.type.lower() not in TAGGED:
            unchecked[r.type] = unchecked.get(r.type, 0) + 1
    for t, n in sorted(unchecked.items()):
        out.append(Finding("COV-002", "warn", t, f"{n} resource(s) of a type these rules do not cover"))
    return out
