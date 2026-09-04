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

from launch import LaunchDescription
from launch.actions import (
    DeclareLaunchArgument,
    ExecuteProcess,
    IncludeLaunchDescription,
)
from launch.launch_description_sources import PythonLaunchDescriptionSource
from launch.substitutions import LaunchConfiguration, PathJoinSubstitution
from launch_ros.substitutions import FindPackageShare


def generate_launch_description():
    introspector_launch_path = PathJoinSubstitution([
        FindPackageShare("rids_introspector"),
        "launch",
        "rids_introspector.launch.py",
    ])

    config_arg = DeclareLaunchArgument(
        "config",
        default_value="config/rids.yaml",
        description="Global RIDS YAML configuration",
    )

    # --- Detector Launch Arguments ---
    baseline_arg = DeclareLaunchArgument(
        "baseline",
        default_value="/home/sergi/intrusion_detection_ws/src/ROS2-Intrusion-Detection/config/baseline_turtlesim.yaml",
        description="Path to the baseline YAML file",
    )

    snapshots_arg = DeclareLaunchArgument(
        "snapshots",
        default_value="results/phase1/snapshots.jsonl",
        description="Path to JSONL snapshots file (passed to introspector as log_file)",
    )

    alerts_arg = DeclareLaunchArgument(
        "alerts",
        default_value="results/phase2/alerts.jsonl",
        description="Path to output alerts JSONL file",
    )

    mode_arg = DeclareLaunchArgument(
        "mode",
        default_value="live",
        choices=["once", "live"],
        description="Execution mode: 'once' or 'live'",
    )

    poll_interval_arg = DeclareLaunchArgument(
        "poll_interval",
        default_value="0.5",
        description="Polling interval in seconds for detector in live mode",
    )

    no_console_arg = DeclareLaunchArgument(
        "no_console",
        default_value="false",
        choices=["true", "false"],
        description="Disable console logging of alerts in detector",
    )

    # --- Introspector Launch Arguments ---
    interface_arg = DeclareLaunchArgument(
        "interface",
        default_value="lo",
        description="Network interface to inspect",
    )

    port_filter_arg = DeclareLaunchArgument(
        "port_filter",
        default_value="udp portrange 7400-7600",
        description="BPF capture filter (use empty string to disable)",
    )

    debug_arg = DeclareLaunchArgument(
        "debug",
        default_value="false",
        choices=["true", "false"],
        description="Enable debug logging",
    )

    gui_arg = DeclareLaunchArgument(
        "gui",
        default_value="false",
        choices=["true", "false"],
        description="Enable real-time graphical visualizer",
    )

    no_terminal_arg = DeclareLaunchArgument(
        "no_terminal",
        default_value="false",
        choices=["true", "false"],
        description="Disable terminal visualization",
    )

    interval_arg = DeclareLaunchArgument(
        "interval",
        default_value="1.0",
        description="Snapshot interval in seconds",
    )

    table_width_arg = DeclareLaunchArgument(
        "table_width",
        default_value="150",
        description="Terminal table width in characters",
    )

    # --- Includes & Nodes ---
    introspector_launch = IncludeLaunchDescription(
        PythonLaunchDescriptionSource(introspector_launch_path),
        launch_arguments={
            "interface": LaunchConfiguration("interface"),
            "port_filter": LaunchConfiguration("port_filter"),
            "debug": LaunchConfiguration("debug"),
            "gui": LaunchConfiguration("gui"),
            "no_terminal": LaunchConfiguration("no_terminal"),
            "log_file": LaunchConfiguration("snapshots"),
            "interval": LaunchConfiguration("interval"),
            "table_width": LaunchConfiguration("table_width"),
        }.items(),
    )

    detector_process = ExecuteProcess(
        cmd=[
            "ros2", "run", "rids_detector", "rids_detector",
            "--config", LaunchConfiguration("config"),
            "--baseline", LaunchConfiguration("baseline"),
            "--snapshots", LaunchConfiguration("snapshots"),
            "--alerts", LaunchConfiguration("alerts"),
            "--mode", LaunchConfiguration("mode"),
            "--poll-interval", LaunchConfiguration("poll_interval"),
            "--no-console", LaunchConfiguration("no_console"),
        ],
        output="screen",
    )

    return LaunchDescription([
        config_arg,
        # Detector arguments
        baseline_arg,
        snapshots_arg,
        alerts_arg,
        mode_arg,
        poll_interval_arg,
        no_console_arg,
        # Introspector arguments
        interface_arg,
        port_filter_arg,
        debug_arg,
        gui_arg,
        no_terminal_arg,
        interval_arg,
        table_width_arg,
        # Actions
        introspector_launch,
        detector_process,
    ])