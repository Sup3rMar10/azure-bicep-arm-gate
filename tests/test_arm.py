"""Reading compiled templates: what is resolved, and what must stay Unknown."""

from bicepgate import MISSING, Unknown, walk
from bicepgate.arm import Resource, contains_unknown


def tpl(resources, params=None, variables=None):
    return {"parameters": params or {}, "variables": variables or {}, "resources": resources}


def res(rtype="Microsoft.Storage/storageAccounts", props=None, **extra):
    return {"type": rtype, "apiVersion": "2023-05-01", "name": "n", "properties": props or {}, **extra}


def one(template, params=None):
    resources = walk(template, params).resources
    assert len(resources) == 1
    return resources[0]


def module(inner, passed, *, scope="inner", name="m"):
    return {"type": "Microsoft.Resources/deployments", "apiVersion": "2022-09-01", "name": name,
            "properties": {"expressionEvaluationOptions": {"scope": scope}, "mode": "Incremental",
                           "parameters": passed, "template": inner}}


# --- parameters and variables ------------------------------------------------------------------------------

def test_a_supplied_parameter_is_resolved():
    t = tpl([res(props={"x": "[parameters('v')]"})], {"v": {"type": "string"}})
    assert one(t, {"v": "hello"}).get("properties.x") == "hello"


def test_a_default_is_used_when_nothing_is_supplied():
    t = tpl([res(props={"x": "[parameters('v')]"})], {"v": {"type": "string", "defaultValue": "dflt"}})
    assert one(t).get("properties.x") == "dflt"


def test_a_supplied_value_beats_the_default():
    t = tpl([res(props={"x": "[parameters('v')]"})], {"v": {"type": "string", "defaultValue": "dflt"}})
    assert one(t, {"v": "given"}).get("properties.x") == "given"


def test_a_parameter_with_no_value_and_no_default_is_unknown():
    t = tpl([res(props={"x": "[parameters('v')]"})], {"v": {"type": "string"}})
    assert isinstance(one(t).get("properties.x"), Unknown)


def test_parameter_names_compare_case_insensitively():
    t = tpl([res(props={"x": "[parameters('MyParam')]"})], {"myParam": {"type": "string"}})
    assert one(t, {"MYPARAM": "v"}).get("properties.x") == "v"


def test_a_default_that_is_a_function_call_is_unknown():
    t = tpl([res(props={"x": "[parameters('loc')]"})], {"loc": {"type": "string", "defaultValue": "[resourceGroup().location]"}})
    assert isinstance(one(t).get("properties.x"), Unknown)


def test_a_variable_is_resolved_including_through_a_parameter():
    t = tpl([res(props={"a": "[variables('plain')]", "b": "[variables('viaParam')]"})], {"p": {"type": "string", "defaultValue": "pv"}},
            {"plain": {"owner": "me"}, "viaParam": "[parameters('p')]"})
    r = one(t)
    assert r.get("properties.a") == {"owner": "me"} and r.get("properties.b") == "pv"


def test_variables_that_refer_to_each_other_do_not_loop():
    t = tpl([res(props={"x": "[variables('a')]"})], variables={"a": "[variables('b')]", "b": "[variables('a')]"})
    assert isinstance(one(t).get("properties.x"), Unknown)


def test_an_undefined_variable_is_unknown():
    assert isinstance(one(tpl([res(props={"x": "[variables('nope')]"})])).get("properties.x"), Unknown)


def test_any_other_expression_is_unknown_and_nothing_is_guessed():
    for expr in ["[concat('a', 'b')]", "[if(true(), 'a', 'b')]", "[reference('x').y]", "[uniqueString('s')]"]:
        assert isinstance(one(tpl([res(props={"x": expr})])).get("properties.x"), Unknown), expr


def test_an_unknown_value_equals_nothing_not_even_itself():
    u = Unknown("[f()]")
    assert u != u and u != "[f()]" and u != Unknown("[f()]") and not (u == True) and not (u == False)  # noqa: E712


def test_an_escaped_bracket_is_a_literal():
    assert one(tpl([res(props={"x": "[[not an expression]"})])).get("properties.x") == "[not an expression]"


def test_plain_strings_that_merely_contain_brackets_are_left_alone():
    assert one(tpl([res(props={"x": "a[1]b", "y": "[open"})])).get("properties.x") == "a[1]b"


def test_values_inside_lists_and_objects_are_resolved():
    t = tpl([res(props={"l": ["[parameters('v')]", {"k": "[parameters('v')]"}]})], {"v": {"type": "string"}})
    assert one(t, {"v": "z"}).get("properties.l") == ["z", {"k": "z"}]


# --- conditions ----------------------------------------------------------------------------------------------

def test_a_resource_whose_condition_is_false_is_not_deployed_and_so_not_checked():
    t = tpl([res(condition="[parameters('on')]")], {"on": {"type": "bool"}})
    assert walk(t, {"on": False}).resources == []
    assert len(walk(t, {"on": True}).resources) == 1


def test_a_condition_that_cannot_be_evaluated_is_checked_anyway():
    t = tpl([res(condition="[equals(parameters('e'), 'prod')]")], {"e": {"type": "string"}})
    assert len(walk(t).resources) == 1


# --- modules ----------------------------------------------------------------------------------------------------

INNER = tpl([res(props={"x": "[parameters('v')]"})], {"v": {"type": "string", "defaultValue": "inner-default"}})


def test_a_module_receives_the_values_its_caller_passes():
    outer = tpl([module(INNER, {"v": {"value": "from-caller"}})])
    r = one(outer)
    assert r.get("properties.x") == "from-caller" and r.path == "main > m"


def test_a_module_value_can_come_from_the_callers_own_parameter():
    outer = tpl([module(INNER, {"v": {"value": "[parameters('top')]"}})], {"top": {"type": "string"}})
    assert one(outer, {"top": "deep"}).get("properties.x") == "deep"


def test_a_module_that_is_not_given_a_value_uses_its_own_default_not_the_callers():
    outer = tpl([module(INNER, {})], {"v": {"type": "string", "defaultValue": "outer-v"}})
    assert one(outer).get("properties.x") == "inner-default"


def test_a_module_parameter_that_is_an_expression_is_unknown():
    outer = tpl([module(INNER, {"v": "[if(true(), createObject('value', 'a'), createObject('value', 'b'))]"})])
    assert isinstance(one(outer).get("properties.x"), Unknown)


def test_a_module_parameter_from_a_reference_is_unknown():
    outer = tpl([module(INNER, {"v": {"reference": {"keyVault": {"id": "x"}, "secretName": "s"}}})])
    assert isinstance(one(outer).get("properties.x"), Unknown)


def test_outer_scope_expressions_see_the_callers_parameters():
    inner = tpl([res(props={"x": "[parameters('top')]"})])
    outer = tpl([module(inner, {}, scope="outer")], {"top": {"type": "string", "defaultValue": "visible"}})
    assert one(outer).get("properties.x") == "visible"


def test_modules_nest():
    mid = tpl([module(INNER, {"v": {"value": "[parameters('m')]"}}, name="leaf")], {"m": {"type": "string"}})
    outer = tpl([module(mid, {"m": {"value": "deepest"}}, name="mid")])
    r = one(outer)
    assert r.get("properties.x") == "deepest" and r.path == "main > mid > leaf"


def test_a_deployment_whose_template_is_not_inline_is_reported_not_skipped():
    link = {"type": "Microsoft.Resources/deployments", "apiVersion": "2022-09-01", "name": "remote",
            "properties": {"mode": "Incremental", "templateLink": {"uri": "https://example.invalid/t.json"}}}
    w = walk(tpl([link]))
    assert w.opaque == ["main > remote"] and w.resources == []


def test_symbolic_name_resources_are_walked():
    t = {"languageVersion": "2.0", "parameters": {}, "resources": {"account": res()}}
    assert len(walk(t).resources) == 1


# --- secrets -----------------------------------------------------------------------------------------------------

def test_secret_looking_parameters_that_are_not_secure_are_listed():
    params = {n: {"type": "string"} for n in ["adminPassword", "clientSecret", "apiKey", "sasToken", "storageConnectionString"]}
    assert {p[1] for p in walk(tpl([], params)).secret_params} == set(params)


def test_secure_parameters_and_ordinary_names_are_not_listed():
    params = {"adminPassword": {"type": "securestring"}, "cfg": {"type": "secureObject"}, "keyVaultName": {"type": "string"},
              "location": {"type": "string"}}
    assert walk(tpl([], {**params, "dbSecret": {"type": "secureObject"}})).secret_params == []


def test_secret_parameters_are_found_inside_modules_too():
    inner = tpl([], {"adminPassword": {"type": "string"}})
    assert [p[0] for p in walk(tpl([module(inner, {})])).secret_params] == ["main > m"]


# --- reading a resource ----------------------------------------------------------------------------------------

def test_get_walks_dotted_paths_case_insensitively_and_reports_missing():
    r = Resource("t", "n", "v", {"properties": {"siteConfig": {"minTlsVersion": "1.2"}}}, "main")
    assert r.get("Properties.SITECONFIG.minTlsVersion") == "1.2"
    assert r.get("properties.siteConfig.nope") is MISSING and r.get("properties.nope.deeper") is MISSING


def test_an_unknown_parent_makes_every_child_unknown():
    r = Resource("t", "n", "v", {"properties": Unknown("[x]")}, "main")
    assert isinstance(r.get("properties.anything.at.all"), Unknown)


def test_contains_unknown_looks_inside():
    assert contains_unknown({"a": [1, {"b": Unknown("[x]")}]}) and not contains_unknown({"a": [1, {"b": 2}]})
