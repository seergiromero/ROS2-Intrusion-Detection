from launch import LaunchDescription
from launch.actions import DeclareLaunchArgument
from launch.substitutions import LaunchConfiguration
from launch_ros.actions import Node

def generate_launch_description():
    return LaunchDescription([
        # Argumentos configurables
        DeclareLaunchArgument(
            'gui',
            default_value='true',
            description='Ejecutar el visualizador gráfico en tiempo real'
        ),
        DeclareLaunchArgument(
            'interface',
            default_value='lo',
            description='Interfaz de red a inspeccionar'
        ),

        # Ejecución del monitor RIDS
        Node(
            package='rids_introspector',
            executable='introspector_node',  # Definido en setup.py / entry_points
            name='rids_introspector',
            output='screen',
            parameters=[{
                'interface': LaunchConfiguration('interface'),
                'gui': LaunchConfiguration('gui'),
            }]
        )
    ])