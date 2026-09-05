"""
MIT License

Copyright (c) 2026 Sergi Romero Valderas

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
"""

from pathlib import Path

import yaml
from launch import LaunchDescription
from launch.actions import (
    DeclareLaunchArgument,
    ExecuteProcess,
    IncludeLaunchDescription,
    OpaqueFunction,
)
from launch.launch_description_sources import PythonLaunchDescriptionSource
from launch.substitutions import LaunchConfiguration, PathJoinSubstitution
from launch_ros.substitutions import FindPackageShare


# ---------------------------------------------------------------------------
# YAML helper
# ---------------------------------------------------------------------------

def _yaml_value(config_path_str, section, name, default):
    """Read a single scalar field from the RIDS YAML."""
    try:
        with open(config_path_str, "r", encoding="utf-8") as stream:
            data = yaml.safe_load(stream) or {}
    except (OSError, yaml.YAMLError):
        return default
    if not isinstance(data, dict):
        return default
    section_data = data.get(section, {})
    if not isinstance(section_data, dict):
        return default
    value = section_data.get(name, default)
    return value if value is not None else default


def _yaml_str(config_path_str, section, name, default):
    """Like ``_yaml_value`` but coerces the result to a string."""
    value = _yaml_value(config_path_str, section, name, default)
    if isinstance(value, bool):
        return "true" if value else "false"
    return str(value)


def _resolve_against_config(value, config_path_str):
    """If a YAML path is relative, anchor it to the YAML's directory."""
    if not isinstance(value, str) or not value or "/" not in value:
        return str(value)
    p = Path(value)
    if p.is_absolute():
        return str(p)
    return str(Path(config_path_str).resolve().parent / p)


def _workspace_root() -> Path:
    """Return the colcon workspace root that holds ``src/ROS2-Intrusion-Detection``."""
    for candidate in Path(__file__).resolve().parents:
        if (candidate / "src" / "ROS2-Intrusion-Detection").is_dir():
            return candidate
    raise RuntimeError(
        "Could not locate the RIDS workspace root (expected a directory "
        "containing src/ROS2-Intrusion-Detection)."
    )


def _resolve_workspace_path(value):
    """Resolve a launch path against the workspace root."""
    if not isinstance(value, str) or not value:
        return str(value)
    p = Path(value)
    if p.is_absolute():
        return str(p)
    return str(_workspace_root() / p)


def _clear_results(config_path_str, section, name, default):
    """Truncate a runtime result file so a fresh launch starts clean.

    Resolves the configured path (anchored to the YAML's directory) and
    empties the file. Missing parent directories are created so the
    consumers can open it in append mode afterwards.
    """
    path = Path(
        _resolve_against_config(
            _yaml_value(config_path_str, section, name, default),
            config_path_str,
        )
    )
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text("", encoding="utf-8")
    except OSError:
        pass


# ---------------------------------------------------------------------------
# Launch description
# ---------------------------------------------------------------------------

def generate_launch_description():
    introspector_launch_path = PathJoinSubstitution([
        FindPackageShare("rids_introspector"),
        "launch",
        "rids_introspector.launch.py",
    ])

    # --- Primary launch arguments --------------------------------------
    config_arg = DeclareLaunchArgument(
        "config",
        default_value=_resolve_workspace_path(
            "src/ROS2-Intrusion-Detection/config/rids.yaml"
        ),
        description=(
            "Path to the global RIDS YAML. All operational tunables "
            "(paths, capture filter, polling rate, ...) live in this file. "
            "Relative paths are resolved against the workspace root "
            "(the directory containing src/ROS2-Intrusion-Detection)."
        ),
    )

    baseline_arg = DeclareLaunchArgument(
        "baseline",
        default_value="src/ROS2-Intrusion-Detection/config/baseline_turtlesim.yaml",
        description=(
            "Optional override of the baseline YAML path. Empty (the "
            "default) means 'use [security].baseline from the config "
            "YAML'. Relative paths are resolved against the workspace "
            "root."
        ),
    )

    mode_arg = DeclareLaunchArgument(
        "mode",
        default_value="live",
        choices=["", "once", "live"],
        description=(
            "Optional override of the detector mode. Empty means 'use "
            "[detector].mode from the config YAML'."
        ),
    )

    reset_arg = DeclareLaunchArgument(
        "reset",
        default_value="true",
        choices=["true", "false"],
        description=(
            "Truncate the snapshots and alerts JSONL files at launch. "
            "True (default) gives every session a clean slate; set to "
            "false to keep history across restarts."
        ),
    )

    # --- Introspector args pulled from the YAML ------------------------
    def _build_actions(context, *_):
        config_path = _resolve_workspace_path(
            LaunchConfiguration("config").perform(context)
        )
        baseline_path = _resolve_workspace_path(
            LaunchConfiguration("baseline").perform(context)
        )
        mode = LaunchConfiguration("mode").perform(context)

        if LaunchConfiguration("reset").perform(context) == "true":
            _clear_results(config_path, "paths", "snapshots", "results/phase1/snapshots.jsonl")
            _clear_results(config_path, "paths", "alerts", "results/phase2/alerts.jsonl")

        introspector_launch = IncludeLaunchDescription(
            PythonLaunchDescriptionSource(introspector_launch_path),
            launch_arguments={
                "interface": _yaml_str(config_path, "introspector", "interface", "lo"),
                "port_filter": _yaml_str(
                    config_path, "introspector", "port_filter",
                    "udp portrange 7400-7600",
                ),
                "debug": _yaml_str(config_path, "introspector", "debug", "false"),
                "gui": _yaml_str(config_path, "introspector", "gui", "false"),
                "no_terminal": _yaml_str(
                    config_path, "introspector", "no_terminal", "true"
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
            }.items(),
        )

        detector_process = ExecuteProcess(
            cmd=[
                "ros2", "run", "rids_detector", "rids_detector",
                "--config", config_path,
                "--baseline", baseline_path,
                "--mode", mode,
            ],
            output="screen",
        )
        return [introspector_launch, detector_process]

    return LaunchDescription([
        config_arg,
        baseline_arg,
        mode_arg,
        reset_arg,
        OpaqueFunction(function=_build_actions),
    ])
