"""
MIT License

Copyright (c) 2026 Sergi Romero Valderas

Tests for the YAML helper functions in rids_detector/launch/rids_detector.launch.py.

The launch file is a regular Python module that exposes ``_yaml_value``,
``_yaml_str``, ``_resolve_against_config``, ``_resolve_config_path`` and
``_config_dir`` as module-level callables. We extract and exercise them here
so the launch-time contract is regression-tested without spinning up ROS 2.
"""

import ast
import textwrap
from pathlib import Path

import pytest
import yaml


LAUNCH_FILE = (
    Path(__file__).resolve().parents[1] / "launch" / "rids_detector.launch.py"
)


def _import_helpers():
    """Import the helper functions from the launch file as plain Python."""
    source = LAUNCH_FILE.read_text(encoding="utf-8")
    tree = ast.parse(source)
    helper_names = {
        "_yaml_value",
        "_yaml_str",
        "_resolve_against_config",
        "_resolve_config_path",
        "_config_dir",
    }
    helpers = [
        node for node in tree.body
        if isinstance(node, ast.FunctionDef) and node.name in helper_names
    ]
    prelude = ast.Module(
        body=[
            ast.Import(names=[ast.alias(name="os", asname=None)]),
            ast.Import(names=[ast.alias(name="yaml", asname=None)]),
            ast.ImportFrom(
                module="pathlib",
                names=[ast.alias(name="Path", asname=None)],
                level=0,
            ),
        ] + helpers,
        type_ignores=[],
    )
    ast.fix_missing_locations(prelude)
    namespace: dict = {"__file__": str(LAUNCH_FILE)}
    exec(compile(prelude, str(LAUNCH_FILE), "exec"), namespace)
    return (
        namespace["_yaml_value"],
        namespace["_yaml_str"],
        namespace["_resolve_against_config"],
        namespace["_resolve_config_path"],
        namespace["_config_dir"],
    )


_yaml_value, _yaml_str, _resolve_against_config, _resolve_config_path, _config_dir = (
    _import_helpers()
)


@pytest.fixture
def config_path(tmp_path):
    cfg = tmp_path / "rids.yaml"
    cfg.write_text(
        textwrap.dedent(
            """
            introspector:
              interface: eth0
              port_filter: "udp portrange 7400-65535"
              interval: 2.5
              gui: true
              no_terminal: false
              table_width: 200
              debug: false

            detector:
              mode: once
              poll_interval: 1.0
              console: false

            paths:
              snapshots: results/snapshots.jsonl
              alerts: results/alerts.jsonl

            security:
              baseline: config/baseline.yaml
              critical_topics:
                - /cmd_vel
            """
        ).lstrip(),
        encoding="utf-8",
    )
    return str(cfg)


# ---------------------------------------------------------------------------
# _yaml_value / _yaml_str
# ---------------------------------------------------------------------------

class TestYamlValue:
    def test_returns_value_from_section(self, config_path):
        assert _yaml_value(config_path, "introspector", "interface", "lo") == "eth0"

    def test_returns_bool_unchanged(self, config_path):
        assert _yaml_value(config_path, "introspector", "gui", False) is True
        assert _yaml_value(config_path, "introspector", "debug", True) is False

    def test_returns_default_when_section_missing(self, config_path):
        assert _yaml_value(config_path, "no_such_section", "key", "default") == "default"

    def test_returns_default_when_file_missing(self, tmp_path):
        missing = tmp_path / "nope.yaml"
        assert _yaml_value(str(missing), "introspector", "interface", "lo") == "lo"


class TestYamlStr:
    def test_bool_serialised_as_lowercase_token(self, config_path):
        assert _yaml_str(config_path, "introspector", "gui", False) == "true"
        assert _yaml_str(config_path, "introspector", "debug", True) == "false"

    def test_number_serialised_as_decimal_string(self, config_path):
        assert _yaml_str(config_path, "introspector", "interval", 1.0) == "2.5"


# ---------------------------------------------------------------------------
# _resolve_against_config
# ---------------------------------------------------------------------------

class TestResolveAgainstConfig:
    def test_relative_path_anchored_to_yaml_dir(self, tmp_path):
        cfg = tmp_path / "rids.yaml"
        result = _resolve_against_config("results/snapshots.jsonl", str(cfg))
        assert result == str(tmp_path / "results" / "snapshots.jsonl")

    def test_absolute_path_returned_unchanged(self, tmp_path):
        cfg = tmp_path / "rids.yaml"
        result = _resolve_against_config("/tmp/abs.jsonl", str(cfg))
        assert result == "/tmp/abs.jsonl"

    def test_non_path_values_returned_unchanged(self, tmp_path):
        cfg = tmp_path / "rids.yaml"
        assert _resolve_against_config("lo", str(cfg)) == "lo"
        assert _resolve_against_config("true", str(cfg)) == "true"


# ---------------------------------------------------------------------------
# _config_dir
# ---------------------------------------------------------------------------

class TestConfigDir:
    def test_returns_an_existing_directory_with_rids_yaml(self):
        config_dir = _config_dir()
        assert isinstance(config_dir, Path)
        assert config_dir.is_dir()
        assert (config_dir / "rids.yaml").is_file()

    def test_prefers_rids_config_dir_env_var(self, tmp_path, monkeypatch):
        fake = tmp_path / "config"
        fake.mkdir()
        (fake / "rids.yaml").write_text("detector: {}\n", encoding="utf-8")
        monkeypatch.setenv("RIDS_CONFIG_DIR", str(fake))
        assert _config_dir() == fake.resolve()

    def test_env_var_without_rids_yaml_raises(self, tmp_path, monkeypatch):
        monkeypatch.setenv("RIDS_CONFIG_DIR", str(tmp_path))
        with pytest.raises(RuntimeError, match="does not contain rids.yaml"):
            _config_dir()


# ---------------------------------------------------------------------------
# _resolve_config_path
# ---------------------------------------------------------------------------

class TestResolveConfigPath:
    def test_relative_path_anchored_to_config_dir(self):
        """A relative path passed to the launch's --config is resolved
        against the RIDS config directory (the one holding rids.yaml).
        """
        result = _resolve_config_path("rids.yaml")
        assert Path(result).is_absolute()
        assert Path(result) == _config_dir() / "rids.yaml"
        assert Path(result).is_file()

    def test_absolute_path_returned_unchanged(self):
        abs_path = "/etc/hosts"
        result = _resolve_config_path(abs_path)
        assert result == abs_path

    def test_empty_string_returned_unchanged(self):
        assert _resolve_config_path("") == ""


# ---------------------------------------------------------------------------
# End-to-end
# ---------------------------------------------------------------------------

class TestEndToEnd:
    def test_introspector_launch_args_built_from_yaml(self, config_path):
        """The same expression the launch file uses to build the
        IncludeLaunchDescription arguments yields the expected dict when
        given a realistic RIDS YAML.
        """
        launch_args = {
            "interface": _yaml_str(config_path, "introspector", "interface", "lo"),
            "port_filter": _yaml_str(
                config_path, "introspector", "port_filter",
                "udp portrange 7400-7600",
            ),
            "debug": _yaml_str(config_path, "introspector", "debug", "false"),
            "gui": _yaml_str(config_path, "introspector", "gui", "false"),
            "no_terminal": _yaml_str(
                config_path, "introspector", "no_terminal", "false"
            ),
            "log_file": _resolve_against_config(
                _yaml_value(
                    config_path, "paths", "snapshots",
                    "results/phase1/snapshots.jsonl",
                ),
                config_path,
            ),
            "interval": _yaml_str(config_path, "introspector", "interval", "1.0"),
            "table_width": _yaml_str(
                config_path, "introspector", "table_width", "150"
            ),
        }

        assert launch_args["interface"] == "eth0"
        assert launch_args["port_filter"] == "udp portrange 7400-65535"
        assert launch_args["interval"] == "2.5"
        assert launch_args["gui"] == "true"
        assert launch_args["table_width"] == "200"
        assert launch_args["debug"] == "false"
        assert launch_args["no_terminal"] == "false"
        # log_file becomes an absolute path anchored to the YAML's dir.
        assert launch_args["log_file"].endswith("results/snapshots.jsonl")
        assert Path(launch_args["log_file"]).is_absolute()
