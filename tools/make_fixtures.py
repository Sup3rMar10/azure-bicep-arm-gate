"""Generate fixtures/good and fixtures/bad plus fixtures/expected.json.

Every bad fixture is a good one with exact text replaced, so it differs from a passing resource by one change and
a failing check can only be about that change. A replacement that does not match exactly once is an error here,
so a typo cannot silently produce a second "good" fixture. Run: python tools/make_fixtures.py
"""

from __future__ import annotations

import json
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent / "fixtures"

TAGS = "var tags = {\n  owner: 'platform'\n  env: 'dev'\n}\n\n"

STORAGE = TAGS + """resource account 'Microsoft.Storage/storageAccounts@2023-05-01' = {
  name: 'stfixture001'
  location: 'westeurope'
  tags: tags
  kind: 'StorageV2'
  sku: {
    name: 'Standard_ZRS'
  }
  properties: {
    supportsHttpsTrafficOnly: true
    minimumTlsVersion: 'TLS1_2'
    allowBlobPublicAccess: false
    allowSharedKeyAccess: false
    publicNetworkAccess: 'Disabled'
    networkAcls: {
      defaultAction: 'Deny'
      bypass: 'AzureServices'
    }
  }
}
"""

VAULT = TAGS + """resource vault 'Microsoft.KeyVault/vaults@2023-07-01' = {
  name: 'kv-fixture-001'
  location: 'westeurope'
  tags: tags
  properties: {
    tenantId: subscription().tenantId
    sku: {
      family: 'A'
      name: 'standard'
    }
    enableRbacAuthorization: true
    enableSoftDelete: true
    softDeleteRetentionInDays: 90
    enablePurgeProtection: true
    publicNetworkAccess: 'Disabled'
    networkAcls: {
      defaultAction: 'Deny'
      bypass: 'AzureServices'
    }
  }
}
"""

NSG = TAGS + """resource nsg 'Microsoft.Network/networkSecurityGroups@2023-11-01' = {
  name: 'nsg-fixture-001'
  location: 'westeurope'
  tags: tags
  properties: {
    securityRules: [
      {
        name: 'allow-https-in'
        properties: {
          priority: 100
          direction: 'Inbound'
          access: 'Allow'
          protocol: 'Tcp'
          sourceAddressPrefix: 'Internet'
          sourcePortRange: '*'
          destinationAddressPrefix: '*'
          destinationPortRange: '443'
        }
      }
      {
        name: 'allow-admin'
        properties: {
          priority: 200
          direction: 'Inbound'
          access: 'Allow'
          protocol: 'Tcp'
          sourceAddressPrefix: '10.20.30.0/24'
          sourcePortRange: '*'
          destinationAddressPrefix: '*'
          destinationPortRange: '22'
        }
      }
      {
        name: 'allow-outbound'
        properties: {
          priority: 300
          direction: 'Outbound'
          access: 'Allow'
          protocol: '*'
          sourceAddressPrefix: '*'
          sourcePortRange: '*'
          destinationAddressPrefix: '*'
          destinationPortRange: '*'
        }
      }
    ]
  }
}
"""

NSG_RULE = """resource nsg 'Microsoft.Network/networkSecurityGroups@2023-11-01' existing = {
  name: 'nsg-existing'
}

resource adminRule 'Microsoft.Network/networkSecurityGroups/securityRules@2023-11-01' = {
  parent: nsg
  name: 'allow-admin'
  properties: {
    priority: 200
    direction: 'Inbound'
    access: 'Allow'
    protocol: 'Tcp'
    sourceAddressPrefix: '10.20.30.0/24'
    sourcePortRange: '*'
    destinationAddressPrefix: '*'
    destinationPortRange: '22'
  }
}
"""

WEB = TAGS + """resource site 'Microsoft.Web/sites@2023-12-01' = {
  name: 'web-fixture-001'
  location: 'westeurope'
  tags: tags
  kind: 'app,linux'
  identity: {
    type: 'SystemAssigned'
  }
  properties: {
    serverFarmId: '/subscriptions/00000000-0000-0000-0000-000000000000/resourceGroups/rg/providers/Microsoft.Web/serverfarms/plan'
    httpsOnly: true
    siteConfig: {
      minTlsVersion: '1.2'
      ftpsState: 'Disabled'
    }
  }
}
"""

BASES = {"storage": STORAGE, "vault": VAULT, "nsg": NSG, "nsg_rule": NSG_RULE, "web": WEB}

# The same properties an attacker would flip, as one-line replacements.
OPEN_STG = [("publicNetworkAccess: 'Disabled'", "publicNetworkAccess: 'Enabled'"), ("defaultAction: 'Deny'", "defaultAction: 'Allow'")]
OPEN_KV = OPEN_STG
SSH_SRC = "sourceAddressPrefix: '10.20.30.0/24'"
SSH_PORT = "destinationPortRange: '22'"


def src(prefix: str):
    return (SSH_SRC, f"sourceAddressPrefix: '{prefix}'")


def port(spec: str):
    return (SSH_PORT, f"destinationPortRange: '{spec}'")


# (name, base, [(old, new), ...], expected rule ids)   expected [] means it must pass cleanly
FIXTURES: list[tuple[str, str, list, list[str]]] = [
    # ---- good (and good variants that sit right next to a bad one) ----
    ("stg_good", "storage", [], []),
    ("stg_good_tls13", "storage", [("TLS1_2", "TLS1_3")], []),
    ("stg_good_public_but_firewalled", "storage", [("publicNetworkAccess: 'Disabled'", "publicNetworkAccess: 'Enabled'")], []),
    ("kv_good", "vault", [], []),
    ("kv_good_retention_30", "vault", [("softDeleteRetentionInDays: 90", "softDeleteRetentionInDays: 30")], []),
    ("kv_good_soft_delete_default", "vault", [("    enableSoftDelete: true\n", "")], []),
    ("nsg_good", "nsg", [], []),
    ("nsg_good_ssh_below_range", "nsg", [src("*"), port("1-21")], []),
    ("nsg_good_between_ssh_and_rdp", "nsg", [src("*"), port("23-3388")], []),
    ("nsg_good_above_rdp", "nsg", [src("*"), port("3390-4000")], []),
    ("nsg_good_https_only_from_anywhere", "nsg", [src("*"), port("443")], []),
    ("nsg_good_deny_ssh_from_anywhere", "nsg", [src("*"), ("access: 'Allow'\n          protocol: 'Tcp'\n          sourceAddressPrefix: '*'", "access: 'Deny'\n          protocol: 'Tcp'\n          sourceAddressPrefix: '*'")], []),
    ("nsg_good_outbound_ssh_from_anywhere", "nsg", [("destinationPortRange: '*'", "destinationPortRange: '22'")], []),
    ("nsg_good_virtualnetwork_tag", "nsg", [src("VirtualNetwork")], []),
    ("nsg_rule_good", "nsg_rule", [], []),
    ("web_good", "web", [], []),
    ("web_good_ftps_only", "web", [("ftpsState: 'Disabled'", "ftpsState: 'FtpsOnly'")], []),
    # ---- storage ----
    ("stg_http", "storage", [("supportsHttpsTrafficOnly: true", "supportsHttpsTrafficOnly: false")], ["STG-001"]),
    ("stg_http_unset", "storage", [("    supportsHttpsTrafficOnly: true\n", "")], ["STG-001"]),
    ("stg_tls10", "storage", [("TLS1_2", "TLS1_0")], ["STG-002"]),
    ("stg_tls11", "storage", [("TLS1_2", "TLS1_1")], ["STG-002"]),
    ("stg_tls_unset", "storage", [("    minimumTlsVersion: 'TLS1_2'\n", "")], ["STG-002"]),
    ("stg_blob_public", "storage", [("allowBlobPublicAccess: false", "allowBlobPublicAccess: true")], ["STG-003"]),
    ("stg_blob_public_unset", "storage", [("    allowBlobPublicAccess: false\n", "")], ["STG-003"]),
    ("stg_open_network", "storage", OPEN_STG, ["STG-004"]),
    ("stg_open_network_unset", "storage", [("    publicNetworkAccess: 'Disabled'\n", ""), ("defaultAction: 'Deny'", "defaultAction: 'Allow'")], ["STG-004"]),
    ("stg_shared_key", "storage", [("allowSharedKeyAccess: false", "allowSharedKeyAccess: true")], ["STG-005"]),
    ("stg_no_tags", "storage", [("  tags: tags\n", "")], ["TAG-001"]),
    ("stg_empty_owner_tag", "storage", [("owner: 'platform'", "owner: ''")], ["TAG-001"]),
    ("stg_missing_env_tag", "storage", [("  env: 'dev'\n", "")], ["TAG-001"]),
    ("stg_many_wrong", "storage", OPEN_STG + [("supportsHttpsTrafficOnly: true", "supportsHttpsTrafficOnly: false"),
                                              ("TLS1_2", "TLS1_0"), ("allowBlobPublicAccess: false", "allowBlobPublicAccess: true"),
                                              ("allowSharedKeyAccess: false", "allowSharedKeyAccess: true"), ("  tags: tags\n", "")],
     ["STG-001", "STG-002", "STG-003", "STG-004", "STG-005", "TAG-001"]),
    # ---- key vault ----
    ("kv_no_purge_protection", "vault", [("enablePurgeProtection: true", "enablePurgeProtection: false")], ["KV-001"]),
    ("kv_purge_protection_unset", "vault", [("    enablePurgeProtection: true\n", "")], ["KV-001"]),
    ("kv_access_policies", "vault", [("enableRbacAuthorization: true", "enableRbacAuthorization: false")], ["KV-002"]),
    ("kv_rbac_unset", "vault", [("    enableRbacAuthorization: true\n", "")], ["KV-002"]),
    ("kv_soft_delete_off", "vault", [("enableSoftDelete: true", "enableSoftDelete: false")], ["KV-003"]),
    ("kv_retention_7", "vault", [("softDeleteRetentionInDays: 90", "softDeleteRetentionInDays: 7")], ["KV-003"]),
    ("kv_retention_29", "vault", [("softDeleteRetentionInDays: 90", "softDeleteRetentionInDays: 29")], ["KV-003"]),
    ("kv_open_network", "vault", OPEN_KV, ["KV-004"]),
    ("kv_no_tags", "vault", [("  tags: tags\n", "")], ["TAG-001"]),
    # ---- network security groups: sources ----
    ("nsg_ssh_from_star", "nsg", [src("*")], ["NSG-001"]),
    ("nsg_ssh_from_internet", "nsg", [src("Internet")], ["NSG-001"]),
    ("nsg_ssh_from_any_keyword", "nsg", [src("Any")], ["NSG-001"]),
    ("nsg_ssh_from_zero_cidr", "nsg", [src("0.0.0.0/0")], ["NSG-001"]),
    ("nsg_ssh_from_zero_cidr_v6", "nsg", [src("::/0")], ["NSG-001"]),
    # ---- network security groups: ports, including both edges of each range ----
    ("nsg_rdp_from_star", "nsg", [src("*"), port("3389")], ["NSG-001"]),
    ("nsg_range_20_25", "nsg", [src("*"), port("20-25")], ["NSG-001"]),
    ("nsg_range_21_22", "nsg", [src("*"), port("21-22")], ["NSG-001"]),
    ("nsg_range_22_23", "nsg", [src("*"), port("22-23")], ["NSG-001"]),
    ("nsg_range_3388_3389", "nsg", [src("*"), port("3388-3389")], ["NSG-001"]),
    ("nsg_range_3389_3390", "nsg", [src("*"), port("3389-3390")], ["NSG-001"]),
    ("nsg_range_spanning_both", "nsg", [src("*"), port("1-5000")], ["NSG-001"]),
    ("nsg_all_ports_star", "nsg", [src("*"), port("*")], ["NSG-001", "NSG-002"]),
    ("nsg_all_ports_range", "nsg", [src("*"), port("0-65535")], ["NSG-001", "NSG-002"]),
    ("nsg_ports_list", "nsg", [src("*"), (SSH_PORT, "destinationPortRanges: [\n            '80'\n            '22'\n          ]")], ["NSG-001"]),
    ("nsg_sources_list", "nsg", [(SSH_SRC, "sourceAddressPrefixes: [\n            '10.0.0.0/8'\n            '*'\n          ]")], ["NSG-001"]),
    ("nsg_rule_ssh_from_star", "nsg_rule", [src("*")], ["NSG-001"]),
    ("nsg_rule_all_ports", "nsg_rule", [src("*"), port("*")], ["NSG-001", "NSG-002"]),
    ("nsg_no_tags", "nsg", [("  tags: tags\n", "")], ["TAG-001"]),
    # ---- app service ----
    ("web_http", "web", [("httpsOnly: true", "httpsOnly: false")], ["WEB-001"]),
    ("web_http_unset", "web", [("    httpsOnly: true\n", "")], ["WEB-001"]),
    ("web_tls10", "web", [("minTlsVersion: '1.2'", "minTlsVersion: '1.0'")], ["WEB-002"]),
    ("web_tls11", "web", [("minTlsVersion: '1.2'", "minTlsVersion: '1.1'")], ["WEB-002"]),
    ("web_ftp_all_allowed", "web", [("ftpsState: 'Disabled'", "ftpsState: 'AllAllowed'")], ["WEB-003"]),
    ("web_no_identity", "web", [("  identity: {\n    type: 'SystemAssigned'\n  }\n", "")], ["WEB-004"]),
    ("web_remote_debugging", "web", [("      ftpsState: 'Disabled'\n", "      ftpsState: 'Disabled'\n      remoteDebuggingEnabled: true\n")], ["WEB-005"]),
    ("web_no_tags", "web", [("  tags: tags\n", "")], ["TAG-001"]),
]

# Fixtures that go through a module, so a value is only visible after resolving parameters.
MODULE = """param httpsOnly bool
param tlsVersion string

resource account 'Microsoft.Storage/storageAccounts@2023-05-01' = {
  name: 'stmodule001'
  location: 'westeurope'
  tags: {
    owner: 'platform'
    env: 'dev'
  }
  kind: 'StorageV2'
  sku: {
    name: 'Standard_ZRS'
  }
  properties: {
    supportsHttpsTrafficOnly: httpsOnly
    minimumTlsVersion: tlsVersion
    allowBlobPublicAccess: false
    allowSharedKeyAccess: false
    publicNetworkAccess: 'Disabled'
    networkAcls: {
      defaultAction: 'Deny'
      bypass: 'AzureServices'
    }
  }
}
"""

MAIN = """param environment string = 'dev'

module storage 'storage_module.bicep' = {
  name: 'storage'
  params: {
    httpsOnly: @@HTTPS@@
    tlsVersion: @@TLS@@
  }
}
"""

COMPOSED = [
    ("composed_good", "true", "'TLS1_2'", []),
    ("composed_http_through_parameter", "false", "'TLS1_2'", ["STG-001"]),
    ("composed_tls_through_parameter", "true", "'TLS1_0'", ["STG-002"]),
    ("composed_tls_from_expression", "true", "environment == 'prod' ? 'TLS1_2' : 'TLS1_0'", ["STG-002"]),  # cannot verify
]

SECRET = """param adminPassword string
param adminUser string = 'azureuser'

resource account 'Microsoft.Storage/storageAccounts@2023-05-01' = {
  name: 'stsecret001'
  location: 'westeurope'
  tags: {
    owner: 'platform'
    env: 'dev'
  }
  kind: 'StorageV2'
  sku: {
    name: 'Standard_ZRS'
  }
  properties: {
    supportsHttpsTrafficOnly: true
    minimumTlsVersion: 'TLS1_2'
    allowBlobPublicAccess: false
    allowSharedKeyAccess: false
    publicNetworkAccess: 'Disabled'
    networkAcls: {
      defaultAction: 'Deny'
      bypass: 'AzureServices'
    }
  }
}

output user string = adminUser
output passwordLength int = length(adminPassword)
"""


def write(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8", newline="\n")


def main() -> None:
    expected: dict[str, list[str]] = {}
    for name, base, edits, rules in FIXTURES:
        text = BASES[base]
        for old, new in edits:
            if text.count(old) != 1:
                raise SystemExit(f"{name}: expected exactly one match for {old!r}, found {text.count(old)}")
            text = text.replace(old, new)
        write(ROOT / ("good" if not rules else "bad") / f"{name}.bicep", text)
        expected[name] = rules
    for name, https, tls, rules in COMPOSED:
        folder = ROOT / ("good" if not rules else "bad") / name
        write(folder / "storage_module.bicep", MODULE)
        write(folder / "main.bicep", MAIN.replace("@@HTTPS@@", https).replace("@@TLS@@", tls))
        expected[name] = rules
    write(ROOT / "bad" / "secret_param_not_secure.bicep", SECRET)
    expected["secret_param_not_secure"] = ["SEC-001"]
    write(ROOT / "expected.json", json.dumps(dict(sorted(expected.items())), indent=2) + "\n")
    print(f"{len(expected)} fixtures: {sum(1 for v in expected.values() if not v)} good, {sum(1 for v in expected.values() if v)} bad")


if __name__ == "__main__":
    main()
