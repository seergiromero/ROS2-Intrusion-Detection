import os
from ament_index_python.packages import get_package_share_directory
from launch import LaunchDescription
from launch.actions import (
    IncludeLaunchDescription,
    SetEnvironmentVariable,
    ExecuteProcess,
    TimerAction,
)
from launch.launch_description_sources import PythonLaunchDescriptionSource

def generate_launch_description():
    pkg_tb3_gazebo = get_package_share_directory("turtlebot3_gazebo")
    pkg_tb3_nav2 = get_package_share_directory("turtlebot3_navigation2")
    pkg_rids_sim = get_package_share_directory("rids_sim")
    map_path = os.path.join(pkg_rids_sim, "maps", "base_map.yaml")

    set_tb3_model = SetEnvironmentVariable("TURTLEBOT3_MODEL", "waffle")

    gazebo_launch = IncludeLaunchDescription(
        PythonLaunchDescriptionSource(
            os.path.join(pkg_tb3_gazebo, "launch", "turtlebot3_world.launch.py")
        ),
        launch_arguments={"gui": "false"}.items(),
    )

    nav2_launch = IncludeLaunchDescription(
        PythonLaunchDescriptionSource(
            os.path.join(pkg_tb3_nav2, "launch", "navigation2.launch.py")
        ),
        launch_arguments={
            "use_sim_time": "true",
            "map": map_path,
        }.items(),
    )

    publish_initial_pose = ExecuteProcess(
        cmd=[
            "ros2",
            "topic",
            "pub",
            "-1",
            "/initialpose",
            "geometry_msgs/msg/PoseWithCovarianceStamped",
            '{header: {frame_id: "map"}, pose: {pose: {position: {x: 0.0, y: 0.0, z: 0.0}}}}',
        ],
        output="screen",
    )

    delayed_initial_pose = TimerAction(period=5.0, actions=[publish_initial_pose])

    return LaunchDescription(
        [
            set_tb3_model,
            gazebo_launch,
            nav2_launch,
            delayed_initial_pose,
        ]
    )
