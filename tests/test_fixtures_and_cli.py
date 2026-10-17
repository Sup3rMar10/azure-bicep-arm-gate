"""The real Bicep compiler, every fixture, the shipped templates, and the command line's exit codes."""

import json
import shutil
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "tools"))

import run_matrix  # noqa: E402

from bicepgate import RULES, CompileError, check, compile_bicep, walk  # noqa: E402
from bicepgate.__main__ import load_params, main  # noqa: E402

EXPECTED = json.loads((ROOT / "fixtures" / "expected.json").read_text(encoding="utf-8"))


@pytest.fixture(scope="session")
def matrix():
    ok, wrong, errors = run_matrix.run()
    return set(ok), wrong, errors


@pytest.mark.parametrize("name", sorted(EXPECTED))
def test_each_fixture_gives_exactly_the_expected_rules(matrix, name):
    ok, wrong, errors = matrix
    assert not [e for e in errors if f" {name}:" in e], errors
    assert not [w for w in wrong if f" {name}:" in w], wrong
    assert name in ok


def test_good_fixtures_are_in_good_and_bad_ones_in_bad():
    for name, rules in EXPECTED.items():
        entry = run_matrix.entry_point(name)
        folder = entry.parent.parent.name if entry.name == "main.bicep" else entry.parent.name
        assert folder == ("bad" if rules else "good"), name


def test_every_rule_that_can_fire_from_bicep_has_a_failing_fixture():
    used = {r for rules in EXPECTED.values() for r in rules}
    assert used == set(RULES) - {"COV-001", "COV-002"}   # those two are about the reader, tested without Bicep


def test_every_expected_rule_is_a_real_rule():
    assert {r for rules in EXPECTED.values() for r in rules} <= set(RULES)


def test_the_matrix_is_large_enough_to_mean_something():
    assert sum(1 for r in EXPECTED.values() if not r) >= 15 and sum(1 for r in EXPECTED.values() if r) >= 50


def test_the_expected_file_covers_exactly_the_fixtures_on_disk():
    on_disk = {p.stem for p in (ROOT / "fixtures").glob("*/*.bicep")} | {p.name for p in (ROOT / "fixtures").glob("*/*") if p.is_dir()}
    assert on_disk == set(EXPECTED)


# --- the harness can fail ---------------------------------------------------------------------------------------------

def test_a_wrong_expectation_is_reported(tmp_path, monkeypatch):
    fake = tmp_path / "fixtures"
    shutil.copytree(ROOT / "fixtures", fake)
    exp = json.loads((fake / "expected.json").read_text(encoding="utf-8"))
    exp["stg_good"] = ["STG-001"]
    exp["stg_http"] = []
    (fake / "expected.json").write_text(json.dumps(exp), encoding="utf-8")
    monkeypatch.setattr(run_matrix, "FIXTURES", fake)
    ok, wrong, errors = run_matrix.run(["stg_good", "stg_http"])
    assert ok == [] and len(wrong) == 2 and errors == []


def test_a_fixture_that_does_not_compile_is_an_error_not_a_pass(tmp_path, monkeypatch):
    fake = tmp_path / "fixtures"
    (fake / "bad").mkdir(parents=True)
    (fake / "bad" / "broken.bicep").write_text("resource x 'Microsoft.Storage/storageAccounts@2023-05-01' = {{{\n", encoding="utf-8")
    (fake / "expected.json").write_text(json.dumps({"broken": ["STG-001"]}), encoding="utf-8")
    monkeypatch.setattr(run_matrix, "FIXTURES", fake)
    ok, wrong, errors = run_matrix.run()
    assert ok == [] and wrong == [] and len(errors) == 1 and "bicep build failed" in errors[0]


# --- the shipped templates ------------------------------------------------------------------------------------------

def test_the_shipped_templates_compile_without_warnings_under_the_strict_linter_config():
    template, warnings = compile_bicep(ROOT / "bicep" / "main.bicep")
    assert warnings == []


def test_the_shipped_templates_pass_the_gate_when_parameters_are_given():
    template, _ = compile_bicep(ROOT / "bicep" / "main.bicep")
    findings = check(walk(template, load_params(str(ROOT / "bicep" / "dev.parameters.json"))))
    assert [f for f in findings if f.severity == "error"] == []
    assert {f.rule for f in findings} == {"COV-002"}   # the app service plan has no rules; that is stated, not hidden


def test_all_four_modules_are_actually_walked():
    template, _ = compile_bicep(ROOT / "bicep" / "main.bicep")
    w = walk(template, load_params(str(ROOT / "bicep" / "dev.parameters.json")))
    assert sorted({r.type for r in w.resources}) == sorted([
        "Microsoft.KeyVault/vaults", "Microsoft.Network/networkSecurityGroups", "Microsoft.Storage/storageAccounts",
        "Microsoft.Web/serverfarms", "Microsoft.Web/sites"])
    assert {r.path.split(" > ")[-1] for r in w.resources} == {"storage", "vault", "network", "web"}


def test_without_parameters_the_ssh_source_cannot_be_verified_and_that_fails():
    template, _ = compile_bicep(ROOT / "bicep" / "main.bicep")
    errors = [f for f in check(walk(template)) if f.severity == "error"]
    assert [(f.rule, f.unverifiable) for f in errors] == [("NSG-001", True)]


def test_the_shipped_storage_name_cannot_exceed_the_limit():
    template, _ = compile_bicep(ROOT / "bicep" / "main.bicep")
    assert "take(" in json.dumps(template)   # the first version overflowed 24 characters and the real compiler said so


# --- the command line -------------------------------------------------------------------------------------------------

def test_exit_codes_for_check(capsys):
    good = str(ROOT / "fixtures" / "good" / "stg_good.bicep")
    bad = str(ROOT / "fixtures" / "bad" / "stg_http.bicep")
    assert main(["check", good]) == 0
    assert main(["check", bad]) == 1
    out = capsys.readouterr().out
    assert "STG-001" in out and "1 error(s)" in out


def test_warnings_alone_do_not_fail_the_gate(capsys):
    assert main(["check", str(ROOT / "fixtures" / "bad" / "stg_shared_key.bicep")]) == 0
    assert "STG-005" in capsys.readouterr().out


def test_a_compile_error_exits_2(tmp_path, capsys):
    broken = tmp_path / "broken.bicep"
    broken.write_text("this is not bicep\n", encoding="utf-8")
    assert main(["check", str(broken)]) == 2
    assert "cannot judge" in capsys.readouterr().err


def test_a_missing_file_exits_2(capsys):
    assert main(["check", str(ROOT / "nope.bicep")]) == 2
    assert main(["whatif", str(ROOT / "nope.json")]) == 2


def test_an_internal_error_exits_2_not_1(monkeypatch, capsys):
    monkeypatch.setattr("bicepgate.__main__.check", lambda w: 1 / 0)
    assert main(["check", str(ROOT / "fixtures" / "good" / "stg_good.bicep")]) == 2
    assert "internal error" in capsys.readouterr().err


def test_a_params_file_resolves_parameters():
    assert load_params(str(ROOT / "bicep" / "dev.parameters.json")) == {
        "prefix": "pay", "environment": "dev", "adminSourcePrefix": "10.20.30.0/24"}
    assert load_params(None) == {}


def test_compile_error_text_names_the_file(tmp_path):
    broken = tmp_path / "x.bicep"
    broken.write_text("param\n", encoding="utf-8")
    with pytest.raises(CompileError) as e:
        compile_bicep(broken)
    assert "x.bicep" in str(e.value)
