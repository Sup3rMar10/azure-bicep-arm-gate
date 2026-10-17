"""Each rule on hand-built resources: it fires on the mistake, stays quiet on correct input, and says so when it cannot tell."""

import pytest

from bicepgate import Resource, Unknown, Walk, check, check_resource
from bicepgate.rules import covers, exposure, port_range, source_is_open

U = Unknown("[something()]")
TAGS = {"owner": "platform", "env": "dev"}


def R(rtype, props=None, **body):
    return Resource(rtype, "r1", "2023-01-01", {"properties": props or {}, **body}, "main")


def ids(findings):
    return sorted({f.rule for f in findings})


STORAGE_OK = {"supportsHttpsTrafficOnly": True, "minimumTlsVersion": "TLS1_2", "allowBlobPublicAccess": False,
              "allowSharedKeyAccess": False, "publicNetworkAccess": "Disabled", "networkAcls": {"defaultAction": "Deny"}}
VAULT_OK = {"enableRbacAuthorization": True, "enableSoftDelete": True, "softDeleteRetentionInDays": 90,
            "enablePurgeProtection": True, "publicNetworkAccess": "Disabled", "networkAcls": {"defaultAction": "Deny"}}
SITE_OK = {"httpsOnly": True, "siteConfig": {"minTlsVersion": "1.2", "ftpsState": "Disabled"}}


def storage(**changes):
    return R("Microsoft.Storage/storageAccounts", {**STORAGE_OK, **changes}, tags=TAGS)


def vault(**changes):
    return R("Microsoft.KeyVault/vaults", {**VAULT_OK, **changes}, tags=TAGS)


def site(identity=True, **config):
    props = {**SITE_OK, "siteConfig": {**SITE_OK["siteConfig"], **config}}
    return R("Microsoft.Web/sites", props, tags=TAGS, **({"identity": {"type": "SystemAssigned"}} if identity else {}))


def test_compliant_resources_have_no_findings():
    assert check_resource(storage()) == [] and check_resource(vault()) == [] and check_resource(site()) == []


# --- storage ---------------------------------------------------------------------------------------------

@pytest.mark.parametrize("change,rule", [
    ({"supportsHttpsTrafficOnly": False}, "STG-001"), ({"supportsHttpsTrafficOnly": "true"}, "STG-001"),  # a string is not the boolean
    ({"minimumTlsVersion": "TLS1_0"}, "STG-002"), ({"minimumTlsVersion": "TLS1_1"}, "STG-002"), ({"minimumTlsVersion": "tls1_2"}, "STG-002"),
    ({"allowBlobPublicAccess": True}, "STG-003"), ({"allowBlobPublicAccess": None}, "STG-003"),
    ({"allowSharedKeyAccess": True}, "STG-005"),
])
def test_storage_violations(change, rule):
    assert ids(check_resource(storage(**change))) == [rule]


@pytest.mark.parametrize("key", ["supportsHttpsTrafficOnly", "minimumTlsVersion", "allowBlobPublicAccess"])
def test_an_unset_security_property_is_a_violation_because_defaults_are_invisible(key):
    props = {k: v for k, v in STORAGE_OK.items() if k != key}
    f = check_resource(R("Microsoft.Storage/storageAccounts", props, tags=TAGS))
    assert len(f) == 1 and "not set" in f[0].message


def test_storage_tls_13_is_fine():
    assert check_resource(storage(minimumTlsVersion="TLS1_3")) == []


@pytest.mark.parametrize("pna,acl,bad", [
    ("Disabled", "Allow", False), ("disabled", "Allow", False),     # private by one route is enough
    ("Enabled", "Deny", False), ("Enabled", "deny", False),
    ("Enabled", "Allow", True), (None, "Allow", True), ("Enabled", None, True), (None, None, True),
    ("SecuredByPerimeter", "Allow", True),
])
def test_exposure(pna, acl, bad):
    props = {k: v for k, v in {"publicNetworkAccess": pna, "networkAcls": {"defaultAction": acl} if acl else None}.items() if v}
    r = R("Microsoft.Storage/storageAccounts", props)
    assert bool(exposure(r, "X-1")) is bad


def test_unknown_exposure_is_unverifiable_unless_the_other_route_settles_it():
    r = R("Microsoft.Storage/storageAccounts", {"publicNetworkAccess": U, "networkAcls": {"defaultAction": "Allow"}})
    assert exposure(r, "X-1")[0].unverifiable
    r2 = R("Microsoft.Storage/storageAccounts", {"publicNetworkAccess": U, "networkAcls": {"defaultAction": "Deny"}})
    assert exposure(r2, "X-1") == []


def test_an_unknown_value_is_reported_as_unverifiable_never_as_fine():
    f = check_resource(storage(minimumTlsVersion=U))
    assert [(x.rule, x.unverifiable, x.severity) for x in f] == [("STG-002", True, "error")]
    assert "cannot be verified" in f[0].message


def test_shared_key_is_only_a_warning():
    assert [f.severity for f in check_resource(storage(allowSharedKeyAccess=True))] == ["warn"]


# --- key vault -------------------------------------------------------------------------------------------

@pytest.mark.parametrize("change,rule", [
    ({"enablePurgeProtection": False}, "KV-001"), ({"enableRbacAuthorization": False}, "KV-002"),
    ({"enableSoftDelete": False}, "KV-003"), ({"softDeleteRetentionInDays": 29}, "KV-003"), ({"softDeleteRetentionInDays": 7}, "KV-003"),
])
def test_vault_violations(change, rule):
    assert ids(check_resource(vault(**change))) == [rule]


def test_vault_retention_boundary_and_the_soft_delete_default():
    assert check_resource(vault(softDeleteRetentionInDays=30)) == []
    props = {k: v for k, v in VAULT_OK.items() if k not in {"enableSoftDelete", "softDeleteRetentionInDays"}}
    assert check_resource(R("Microsoft.KeyVault/vaults", props, tags=TAGS)) == []   # on by default and cannot be turned off


def test_vault_retention_given_as_a_bool_is_not_mistaken_for_a_number():
    assert check_resource(vault(softDeleteRetentionInDays=False)) == []  # not an int: nothing to compare, ARM would reject it


def test_vault_open_network():
    assert ids(check_resource(vault(publicNetworkAccess="Enabled", networkAcls={"defaultAction": "Allow"}))) == ["KV-004"]


def test_vault_unknown_retention_is_unverifiable():
    f = check_resource(vault(softDeleteRetentionInDays=U))
    assert [(x.rule, x.unverifiable) for x in f] == [("KV-003", True)]


# --- network security groups: the helpers ----------------------------------------------------------------------

@pytest.mark.parametrize("prefix,expected", [
    ("*", True), ("Any", True), ("any", True), ("Internet", True), ("internet", True), ("0.0.0.0/0", True), ("::/0", True),
    ("0.0.0.0/1", False), ("10.0.0.0/8", False), ("203.0.113.7", False), ("VirtualNetwork", False), ("AzureLoadBalancer", False),
    (U, None), (None, None), (5, None),
])
def test_source_is_open(prefix, expected):
    assert source_is_open(prefix) is expected


@pytest.mark.parametrize("spec,expected", [
    ("22", (22, 22)), ("*", (0, 65535)), ("20-25", (20, 25)), ("0-65535", (0, 65535)), (" 22 ", (22, 22)),
    ("25-20", None), ("22-", None), ("-5", None), ("abc", None), ("0-65536", None), ("", None), (U, None), (22, None),
])
def test_port_range(spec, expected):
    assert port_range(spec) == expected


@pytest.mark.parametrize("spec,expected", [
    ("22", True), ("3389", True), ("21", False), ("23", False), ("3388", False), ("3390", False),
    ("21-22", True), ("22-23", True), ("20-25", True), ("3388-3389", True), ("3389-3390", True),
    ("23-3388", False), ("1-21", False), ("3390-4000", False), ("0-21", False), ("1-5000", True), ("*", True),
    ("bogus", None), (U, None),
])
def test_covers_ssh_and_rdp_at_both_edges_of_every_range(spec, expected):
    assert covers([spec], [22, 3389]) is expected


def test_covers_a_list_is_true_if_any_member_hits_and_unknown_only_if_nothing_hits():
    assert covers(["80", "22"], [22]) is True
    assert covers(["80", "443"], [22]) is False
    assert covers(["80", U], [22]) is None
    assert covers(["22", U], [22]) is True


# --- network security groups: rules ------------------------------------------------------------------------------

def rule(src="10.0.0.0/24", port="22", direction="Inbound", access="Allow", **extra):
    return {"direction": direction, "access": access, "sourceAddressPrefix": src, "destinationPortRange": port, **extra}


def nsg(*rules):
    return R("Microsoft.Network/networkSecurityGroups", {"securityRules": [{"name": f"r{i}", "properties": p} for i, p in enumerate(rules)]}, tags=TAGS)


def test_a_restricted_source_is_fine():
    assert check_resource(nsg(rule())) == []


@pytest.mark.parametrize("kw,expected", [
    (dict(src="*"), ["NSG-001"]), (dict(src="Internet", port="3389"), ["NSG-001"]), (dict(src="*", port="*"), ["NSG-001", "NSG-002"]),
    (dict(src="*", port="0-65535"), ["NSG-001", "NSG-002"]), (dict(src="*", port="1-65534"), ["NSG-001"]),  # almost everything
    (dict(src="*", port="443"), []), (dict(src="*", port="22", access="Deny"), []), (dict(src="*", port="22", direction="Outbound"), []),
    (dict(src="*", port="23-3388"), []), (dict(src="*", port="3389-3390"), ["NSG-001"]),
])
def test_nsg_rule_cases(kw, expected):
    assert ids(check_resource(nsg(rule(**kw)))) == expected


def test_list_valued_properties_are_read():
    p = {"direction": "Inbound", "access": "Allow", "sourceAddressPrefixes": ["10.0.0.0/8", "*"], "destinationPortRanges": ["80", "3389"]}
    assert ids(check_resource(nsg(p))) == ["NSG-001"]


def test_one_bad_rule_among_good_ones_is_found_and_named():
    f = check_resource(nsg(rule(), rule(src="*"), rule(port="443")))
    assert len(f) == 1 and "'r1'" in f[0].message


def test_nsg_keys_are_case_insensitive():
    p = {"Direction": "inbound", "Access": "ALLOW", "SourceAddressPrefix": "*", "DestinationPortRange": "22"}
    assert ids(check_resource(nsg(p))) == ["NSG-001"]


def test_an_unknown_source_on_an_ssh_allow_cannot_be_verified():
    f = check_resource(nsg(rule(src=U)))
    assert [(x.rule, x.unverifiable) for x in f] == [("NSG-001", True)]


def test_an_unknown_value_on_a_rule_that_is_already_safe_is_not_noise():
    assert check_resource(nsg(rule(src=U, port="443"))) == []                       # 443 is not SSH or RDP
    assert check_resource(nsg(rule(src=U, access="Deny"))) == []                    # a Deny is not an exposure
    assert check_resource(nsg(rule(src="10.0.0.0/24", port=U))) == []               # a private source is not an exposure


def test_unknown_ports_from_anywhere_cannot_be_verified():
    assert [x.unverifiable for x in check_resource(nsg(rule(src="*", port=U)))] == [True, True]  # NSG-001 and NSG-002


def test_unknown_direction_or_access_cannot_be_verified():
    assert ids(check_resource(nsg(rule(src="*", direction=U)))) == ["NSG-001"]
    assert ids(check_resource(nsg(rule(src="*", access=U)))) == ["NSG-001"]


def test_unknown_rule_list_cannot_be_verified():
    f = check_resource(R("Microsoft.Network/networkSecurityGroups", {"securityRules": U}, tags=TAGS))
    assert [(x.rule, x.unverifiable) for x in f] == [("NSG-001", True)]


def test_a_standalone_security_rule_resource_is_checked_like_an_embedded_one():
    bad = R("Microsoft.Network/networkSecurityGroups/securityRules", rule(src="*"))
    good = R("Microsoft.Network/networkSecurityGroups/securityRules", rule())
    assert ids(check_resource(bad)) == ["NSG-001"] and check_resource(good) == []


def test_an_nsg_with_no_rules_is_fine():
    assert check_resource(R("Microsoft.Network/networkSecurityGroups", {}, tags=TAGS)) == []


# --- app service ------------------------------------------------------------------------------------------------

@pytest.mark.parametrize("make,rule_id", [
    (lambda: R("Microsoft.Web/sites", {**SITE_OK, "httpsOnly": False}, tags=TAGS, identity={"type": "SystemAssigned"}), "WEB-001"),
    (lambda: site(minTlsVersion="1.0"), "WEB-002"), (lambda: site(minTlsVersion="1.1"), "WEB-002"),
    (lambda: site(ftpsState="AllAllowed"), "WEB-003"), (lambda: site(remoteDebuggingEnabled=True), "WEB-005"),
    (lambda: site(identity=False), "WEB-004"),
])
def test_site_violations(make, rule_id):
    assert ids(check_resource(make())) == [rule_id]


def test_site_good_variants():
    assert check_resource(site(ftpsState="FtpsOnly")) == [] and check_resource(site(minTlsVersion="1.3")) == []
    assert check_resource(site(remoteDebuggingEnabled=False)) == []


def test_site_identity_types():
    for t in ("SystemAssigned", "UserAssigned", "SystemAssigned, UserAssigned"):
        assert check_resource(R("Microsoft.Web/sites", SITE_OK, tags=TAGS, identity={"type": t})) == []
    assert ids(check_resource(R("Microsoft.Web/sites", SITE_OK, tags=TAGS, identity={"type": "None"}))) == ["WEB-004"]


def test_a_deployment_slot_gets_the_same_rules():
    assert ids(check_resource(R("Microsoft.Web/sites/slots", {**SITE_OK, "httpsOnly": False}, tags=TAGS))) == ["WEB-001", "WEB-004"]


def test_site_identity_warning_is_a_warning_and_debugging_is_an_error():
    sev = {f.rule: f.severity for f in check_resource(site(identity=False, remoteDebuggingEnabled=True))}
    assert sev == {"WEB-004": "warn", "WEB-005": "error"}


# --- tags --------------------------------------------------------------------------------------------------------

@pytest.mark.parametrize("tags,bad", [
    (TAGS, False), ({"Owner": "x", "ENV": "y"}, False), ({"owner": "x", "env": "y", "extra": "z"}, False),
    ({"owner": "x"}, True), ({"env": "y"}, True), ({"owner": "", "env": "y"}, True), ({"owner": "  ", "env": "y"}, True),
    ({"owner": 5, "env": "y"}, True), ({}, True), (None, True), ("not-a-dict", True),
])
def test_required_tags(tags, bad):
    body = {} if tags is None else {"tags": tags}
    r = R("Microsoft.Storage/storageAccounts", STORAGE_OK, **body)
    assert (ids(check_resource(r)) == ["TAG-001"]) is bad


def test_tags_that_are_unknown_cannot_be_verified():
    f = check_resource(R("Microsoft.Storage/storageAccounts", STORAGE_OK, tags=U))
    assert [(x.rule, x.unverifiable) for x in f] == [("TAG-001", True)]
    f2 = check_resource(R("Microsoft.Storage/storageAccounts", STORAGE_OK, tags={"owner": U, "env": "dev"}))
    assert [(x.rule, x.unverifiable) for x in f2] == [("TAG-001", True)]


def test_types_without_rules_are_not_required_to_have_tags():
    assert check_resource(R("Microsoft.Web/serverfarms")) == []


# --- the whole-template checks -------------------------------------------------------------------------------------

def test_secret_parameters_opaque_deployments_and_uncovered_types_are_reported():
    w = Walk(resources=[R("Microsoft.Web/serverfarms"), R("Microsoft.Web/serverfarms"), storage()],
             secret_params=[("main > m", "adminPassword", "string")], opaque=["main > remote"])
    f = check(w)
    by_rule = {x.rule: x for x in f}
    assert set(by_rule) == {"SEC-001", "COV-001", "COV-002"}
    assert by_rule["COV-001"].unverifiable and by_rule["COV-001"].severity == "error"
    assert by_rule["COV-002"].severity == "warn" and "2 resource" in by_rule["COV-002"].message


def test_a_clean_template_has_no_findings():
    assert check(Walk(resources=[storage(), vault(), site()])) == []
