from glob import glob
import os
from setuptools import find_packages, setup

package_name = 'rids_introspector'

setup(
    name=package_name,
    version='0.0.0',
    packages=find_packages(exclude=['test']),
    data_files=[
        ('share/ament_index/resource_index/packages',
            ['resource/' + package_name]),
        ('share/' + package_name, ['package.xml']),
        (os.path.join('share', package_name, 'launch'), glob(os.path.join('launch', '*launch.[pxy][yma]'))),
    ],
    install_requires=[
        'setuptools',
        'networkx',
        'matplotlib',
        'scapy',
    ],
    zip_safe=True,
    maintainer='Sergi Romero Valderas',
    maintainer_email='sromerovalderas@gmail.com',
    description='Real-time RTPS Introspection and Security Monitor for ROS 2',
    license='MIT',
    extras_require={
        'test': [
            'pytest',
        ],
    },
    entry_points={
        'console_scripts': [
            'introspector_node = rids_introspector.main:main',
        ],
    },
)