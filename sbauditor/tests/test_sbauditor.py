import json

from . import context
from sbauditor import SBAuditor
from .test_modules.plugin1 import plugin_func_1


def test_sbauditor_plugin_loader():
    app = SBAuditor(name="test controller", search_path="./tests/test_modules")
    app.load_plugins()
    for k, v in app.registry.checks["test"].items():
        assert k == "plugin_func_1"


def test_sbauditor_plugin_loader_named():
    app = SBAuditor(name="test controller", search_path="./tests/test_modules")
    app.load_plugins(plugin_name="plugin1")
    for k, v in app.registry.checks["test"].items():
        assert k == "plugin_func_1"


def test_sbauditor_plugin_run_checks():
    app = SBAuditor(name="test controller", search_path="./tests/test_modules")
    # Since other tests are importing auditor modules that register checks in the
    # registry, it is possible checks other than those in the search_path will be
    # loaded and run here.  This statement clears the checks dictionary prior to
    # calling load_plugins
    app.registry.checks.clear()
    app.load_plugins()
    for result in app.run_checks():
        assert result == {"SchemaVersion": "2018-10-08", "Id": "test-finding"}


def test_sbauditor_plugin_run_one_check():
    app = SBAuditor(name="test controller", search_path="./tests/test_modules")
    app.load_plugins(plugin_name="plugin1")
    for result in app.run_checks(requested_check_name="plugin_func_1"):
        assert result == {"SchemaVersion": "2018-10-08", "Id": "test-finding"}
