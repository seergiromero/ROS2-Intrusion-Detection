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
from launch.actions import DeclareLaunchArgument, ExecuteProcess
from launch.substitutions import LaunchConfiguration

def generate_launch_description():
    return LaunchDescription([
        DeclareLaunchArgument(
            'interface',
            default_value='lo',
            description='Network interface to inspect'
        ),
        DeclareLaunchArgument(
            'port_filter',
            default_value='udp portrange 7400-7600',
            description='BPF capture filter (use empty string to disable)'
        ),
        DeclareLaunchArgument(
            'debug',
            default_value='false',
            description='Enable debug logging'
        ),
        DeclareLaunchArgument(
            'gui',
            default_value='false',
            description='Enable the real-time graphical visualizer (Matplotlib)'
        ),
        DeclareLaunchArgument(
            'no_terminal',
            default_value='false',
            description='Disable terminal visualization'
        ),
        DeclareLaunchArgument(
            'log_file',
            default_value='snapshots.jsonl',
            description='Output file path for snapshots'
        ),
        DeclareLaunchArgument(
            'interval',
            default_value='1.0',
            description='Snapshot interval in seconds'
        ),
        DeclareLaunchArgument(
            'table_width',
            default_value='150',
            description='Terminal table width in characters'
        ),

        ExecuteProcess(
            cmd=[
                'ros2', 'run', 'rids_introspector', 'introspector_node',
                '--interface', LaunchConfiguration('interface'),
                '--port-filter', LaunchConfiguration('port_filter'),
                '--debug', LaunchConfiguration('debug'),
                '--gui', LaunchConfiguration('gui'),
                '--no-terminal', LaunchConfiguration('no_terminal'),
                '--log-file', LaunchConfiguration('log_file'),
                '--interval', LaunchConfiguration('interval'),
                '--table-width', LaunchConfiguration('table_width'),
            ],
            output='screen',
        )
    ])