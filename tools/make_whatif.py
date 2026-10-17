"""Generate whatif/*.json: hand-written results in the shape `az deployment group what-if --no-pretty-print` emits.

NO real what-if produced these. They follow the documented structure (status, changes[] with changeType,
resourceId, before, after) so the gate can be exercised; a real result may carry more fields. Run:
python tools/make_whatif.py
"""

from __future__ import annotations

import copy
import json
from pathlib import Path

OUT = Path(__file__).resolve().parent.parent / "whatif"
SUB = "/subscriptions/00000000-0000-0000-0000-000000000000/resourceGroups/rg-pay/providers"

STORAGE = {
    "type": "Microsoft.Storage/storageAccounts", "name": "stpaydev", "location": "westeurope",
    "tags": {"owner": "platform", "env": "dev"}, "kind": "StorageV2", "sku": {"name": "Standard_ZRS"},
    "properties": {"supportsHttpsTrafficOnly": True, "minimumTlsVersion": "TLS1_2", "allowBlobPublicAccess": False,
                   "allowSharedKeyAccess": False, "publicNetworkAccess": "Disabled",
                   "networkAcls": {"defaultAction": "Deny", "bypass": "AzureServices"}},
}
VAULT = {
    "type": "Microsoft.KeyVault/vaults", "name": "pay-dev-kv", "location": "westeurope",
    "tags": {"owner": "platform", "env": "dev"},
    "properties": {"enableRbacAuthorization": True, "enableSoftDelete": True, "softDeleteRetentionInDays": 90,
                   "enablePurgeProtection": True, "publicNetworkAccess": "Disabled",
                   "networkAcls": {"defaultAction": "Deny", "bypass": "AzureServices"}},
}
SSH_RULE = {
    "type": "Microsoft.Network/networkSecurityGroups/securityRules", "name": "allow-admin",
    "properties": {"priority": 200, "direction": "Inbound", "access": "Allow", "protocol": "Tcp",
                   "sourceAddressPrefix": "10.20.30.0/24", "sourcePortRange": "*",
                   "destinationAddressPrefix": "*", "destinationPortRange": "22"},
}


def with_props(base: dict, **props) -> dict:
    out = copy.deepcopy(base)
    out["properties"].update(props)
    return out


def change(kind: str, rid: str, before=None, after=None) -> dict:
    out = {"resourceId": f"{SUB}/{rid}", "changeType": kind}
    if before is not None:
        out["before"] = before
    if after is not None:
        out["after"] = after
    return out


def doc(*changes: dict, status: str = "Succeeded", **extra) -> dict:
    return {"status": status, "changes": list(changes), **extra}


STG = "Microsoft.Storage/storageAccounts/stpaydev"
KV = "Microsoft.KeyVault/vaults/pay-dev-kv"
NSG = "Microsoft.Network/networkSecurityGroups/nsg"
BAD_STORAGE = with_props(STORAGE, supportsHttpsTrafficOnly=False)

FILES = {
    "clean_create": doc(change("Create", STG, after=STORAGE), change("NoChange", KV)),
    "create_noncompliant": doc(change("Create", STG, after=BAD_STORAGE)),
    "create_nested_ssh_from_anywhere": doc(change("Create", f"{NSG}/securityRules/allow-admin",
                                                  after=with_props(SSH_RULE, sourceAddressPrefix="*"))),
    "modify_weakens": doc(change("Modify", STG, before=STORAGE, after=BAD_STORAGE)),
    "modify_already_bad": doc(change("Modify", STG, before=BAD_STORAGE, after=with_props(BAD_STORAGE, allowSharedKeyAccess=True))),
    "modify_fixes": doc(change("Modify", STG, before=BAD_STORAGE, after=STORAGE)),
    "delete_key_vault": doc(change("Delete", KV, before=VAULT)),
    "delete_storage_account": doc(change("Delete", STG, before=STORAGE)),
    "delete_unprotected": doc(change("Delete", NSG, before={"type": "Microsoft.Network/networkSecurityGroups", "name": "nsg"})),
    "ignored_resource": doc(change("Ignore", "Microsoft.Foo/things/t1")),
    # documents the gate must refuse to judge
    "bad_status_failed": doc(status="Failed"),
    "bad_error_field": doc(error={"code": "InvalidTemplate", "message": "boom"}),
    "bad_unknown_change_type": doc(change("Replace", STG, after=STORAGE)),
    "bad_create_without_after": doc(change("Create", STG)),
    "bad_not_a_what_if_result": {"hello": "world"},
    "bad_resource_id": {"status": "Succeeded", "changes": [{"changeType": "Create", "resourceId": "not-an-id", "after": {}}]},
}


def main() -> None:
    OUT.mkdir(exist_ok=True)
    for name, content in FILES.items():
        (OUT / f"{name}.json").write_text(json.dumps(content, indent=2) + "\n", encoding="utf-8", newline="\n")
    print(f"{len(FILES)} what-if documents")


if __name__ == "__main__":
    main()
