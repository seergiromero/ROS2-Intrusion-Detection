from setuptools import find_packages, setup
from glob import glob
import os

package_name = 'rids_detector'

setup(
    name=package_name,
    version='0.0.0',
    packages=find_packages(exclude=['test']),
    data_files=[
        ('share/ament_index/resource_index/packages',
            ['resource/' + package_name]),
        ('share/' + package_name, ['package.xml']),
        (os.path.join('share', package_name, 'config'), glob('config/*.yaml')),
        (os.path.join('share', package_name, 'launch'), glob(os.path.join('launch', '*launch.[pxy][yma]'))),
    ],
    install_requires=['setuptools', 'PyYAML'],
    zip_safe=True,
    maintainer='Sergi Romero Valderas',
    maintainer_email='sromerovalderas@gmail.com',
    description='Baseline-based anomaly detector for ROS 2 RTPS graphs',
    license='MIT',
    extras_require={
        'test': [
            'pytest',
        ],
    },
    entry_points={
        'console_scripts': [
            'rids_detector = rids_detector.main:main',
        ],
    },
)
