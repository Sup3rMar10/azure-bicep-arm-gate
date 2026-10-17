"""The what-if gate, and the pipeline's own permissions."""

import json
from pathlib import Path

import pytest
import yaml

from bicepgate import WhatIfError, evaluate
from bicepgate.__main__ import main
from bicepgate.whatif import type_of

ROOT = Path(__file__).resolve().parent.parent
WHATIF = ROOT / "whatif"


def load(name):
    return json.loads((WHATIF / f"{name}.json").read_text(encoding="utf-8"))


def summary(name):
    r = evaluate(load(name))
    return sorted((f.rule, f.severity) for f in r.findings), r.counts


# --- what it decides -----------------------------------------------------------------------------------------

@pytest.mark.parametrize("name,expected", [
    ("clean_create", []),
    ("create_noncompliant", [("STG-001", "error")]),
    ("create_nested_ssh_from_anywhere", [("NSG-001", "error")]),
    ("modify_weakens", [("STG-001", "error")]),
    ("modify_fixes", []),
    ("delete_key_vault", [("WI-001", "error")]),
    ("delete_storage_account", [("WI-001", "error")]),
    ("delete_unprotected", [("WI-002", "warn")]),
    ("ignored_resource", [("WI-003", "warn")]),
])
def test_what_if_results(name, expected):
    assert summary(name)[0] == expected


def test_a_change_to_an_already_bad_resource_only_warns_but_a_new_violation_fails():
    findings, _ = summary("modify_already_bad")
    assert all(sev == "warn" for _, sev in findings) and ("STG-001", "warn") in findings
    # The same resource created from scratch is an error: the ratchet only forgives what was already true.
    assert ("STG-001", "error") in summary("create_noncompliant")[0]


def test_the_pre_existing_note_is_in_the_message():
    msgs = [f.message for f in evaluate(load("modify_already_bad")).findings if f.rule == "STG-001"]
    assert msgs and "already the case before this change" in msgs[0]


def test_counts_are_reported_per_change_type():
    assert summary("clean_create")[1] == {"Create": 1, "NoChange": 1}


def test_no_change_and_deploy_do_not_need_a_body():
    doc = {"status": "Succeeded", "changes": [{"changeType": "NoChange", "resourceId": "/subscriptions/s/resourceGroups/g/providers/Microsoft.Web/serverfarms/p"},
                                               {"changeType": "Deploy", "resourceId": "/subscriptions/s/resourceGroups/g/providers/Microsoft.Resources/deployments/d"}]}
    assert evaluate(doc).findings == []


def test_what_if_has_resolved_values_so_nothing_is_unverifiable():
    for name in ("create_noncompliant", "modify_weakens", "create_nested_ssh_from_anywhere"):
        assert not any(f.unverifiable for f in evaluate(load(name)).findings)


@pytest.mark.parametrize("rid,expected", [
    ("/subscriptions/s/resourceGroups/g/providers/Microsoft.Storage/storageAccounts/x", "microsoft.storage/storageaccounts"),
    ("/subscriptions/s/resourceGroups/g/providers/Microsoft.Network/networkSecurityGroups/n/securityRules/r",
     "microsoft.network/networksecuritygroups/securityrules"),
    ("/subscriptions/s/resourceGroups/g/providers/Microsoft.Sql/servers/srv/databases/db", "microsoft.sql/servers/databases"),
    ("/providers/Microsoft.Management/managementGroups/mg", "microsoft.management/managementgroups"),
])
def test_resource_type_from_id(rid, expected):
    assert type_of(rid) == expected


@pytest.mark.parametrize("rid", ["not-an-id", "/subscriptions/s/resourceGroups/g", "/subscriptions/s/providers/Microsoft.Storage",
                                 "/subscriptions/s/providers/Microsoft.Storage/storageAccounts"])
def test_malformed_resource_ids_are_refused(rid):
    with pytest.raises(WhatIfError):
        type_of(rid)


# --- what it refuses to judge ---------------------------------------------------------------------------------------

@pytest.mark.parametrize("name", ["bad_status_failed", "bad_error_field", "bad_unknown_change_type", "bad_create_without_after",
                                  "bad_not_a_what_if_result", "bad_resource_id"])
def test_documents_it_cannot_judge_raise(name):
    with pytest.raises(WhatIfError):
        evaluate(load(name))


@pytest.mark.parametrize("name", ["bad_status_failed", "bad_error_field", "bad_unknown_change_type", "bad_create_without_after",
                                  "bad_not_a_what_if_result", "bad_resource_id"])
def test_and_the_command_exits_2_for_them(name, capsys):
    assert main(["whatif", str(WHATIF / f"{name}.json")]) == 2
    assert "cannot judge" in capsys.readouterr().err


@pytest.mark.parametrize("doc", [[], "text", None, {"status": "Succeeded"}, {"status": "Succeeded", "changes": {}},
                                 {"status": "Succeeded", "changes": [5]}, {"status": "Succeeded", "changes": [{"changeType": "Create"}]}])
def test_wrong_shapes_raise_whatiferror_not_a_crash(doc):
    with pytest.raises((WhatIfError, AttributeError)) as e:
        evaluate(doc)
    assert isinstance(e.value, WhatIfError), "a crash here would exit 1 and look like a finding"


def test_exit_codes_for_what_if(capsys):
    assert main(["whatif", str(WHATIF / "clean_create.json")]) == 0
    assert main(["whatif", str(WHATIF / "modify_weakens.json")]) == 1
    assert main(["whatif", str(WHATIF / "delete_unprotected.json")]) == 0   # a warning does not fail it


# --- the workflows --------------------------------------------------------------------------------------------------------

WORKFLOWS = ROOT / ".github" / "workflows"
FILES = sorted(WORKFLOWS.glob("*.yml"))


def wf(path):
    return yaml.safe_load(path.read_text(encoding="utf-8"))


def test_there_are_workflows_to_check():
    assert {p.name for p in FILES} >= {"ci.yml", "whatif.yml"}


@pytest.mark.parametrize("path", FILES, ids=lambda p: p.name)
def test_workflow_permissions_default_to_read_only(path):
    assert wf(path).get("permissions") == {"contents": "read"}


@pytest.mark.parametrize("path", FILES, ids=lambda p: p.name)
def test_no_stored_azure_credentials(path):
    text = path.read_text(encoding="utf-8")
    for needle in ("creds:", "AZURE_CREDENTIALS", "client-secret", "ARM_CLIENT_SECRET", "AZURE_CLIENT_SECRET", "pull_request_target"):
        assert needle not in text


def test_only_the_job_that_logs_in_to_azure_may_mint_an_oidc_token():
    for path in FILES:
        for name, job in wf(path)["jobs"].items():
            logs_in = any("azure/login" in str(s.get("uses", "")) for s in job.get("steps", []))
            assert (job.get("permissions", {}).get("id-token") == "write") == logs_in, f"{path.name}:{name}"


def test_the_what_if_job_is_skipped_without_the_variable_and_uses_variables_for_identifiers():
    job = wf(WORKFLOWS / "whatif.yml")["jobs"]["whatif"]
    assert "AZURE_PLAN_CLIENT_ID" in job["if"]
    login = next(s for s in job["steps"] if "azure/login" in str(s.get("uses", "")))
    assert all(login["with"][k].startswith("${{ vars.") for k in ("client-id", "tenant-id", "subscription-id"))


def test_ci_pins_the_bicep_version_it_was_tested_with():
    env = wf(WORKFLOWS / "ci.yml")["env"]
    assert env["BICEP_VERSION"].startswith("v0.")
    assert "${BICEP_VERSION}" in (WORKFLOWS / "ci.yml").read_text(encoding="utf-8")
