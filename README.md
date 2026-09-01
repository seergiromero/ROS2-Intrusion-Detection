# RIDS — ROS2 Network Intrusion Detection System

🚧 **Work in progress.** This README will be expanded as the project phases advance.

## Overview

Intrusion detection system for the ROS2/DDS communication graph of a mobile robot.
It monitors normal system traffic, learns a behavioral baseline, and detects anomalous 
activity (rogue nodes, unauthorized publishers, floods) using a combination of deterministic 
rules and an anomaly detection model.

## Current Status

- [x] Phase 0 — Simulation environment (TurtleBot3 Waffle + Nav2)
- [ ] Phase 1 — ROS2 graph introspection (`rids_introspector`)
- [ ] Phase 2 — Anomaly detection (`rids_detector`)
- [ ] Phase 3 — Attack simulation (`rids_attacker`)
- [ ] Phase 4 — Active response (optional)

## Architecture (Overview)

The system is divided into independent modules that communicate via ROS2 topics:

- **rids_introspector** (Python): Builds a real-time model of the node/topic graph.
- **rids_detector** (Python + PyTorch): Compares the observed graph against a baseline and 
  detects anomalies using rules + a Variational Autoencoder.
- **rids_attacker** (C++): Simulates attacks (rogue node, malicious publisher, flood) against 
  the system, used exclusively to validate the detector.

## Motivation

DDS, the underlying middleware used by ROS2, assumes a trusted network environment by default: 
any node can discover the complete graph and publish to critical topics like `/cmd_vel` without 
authentication. This project explores how to detect such malicious activity in real time, 
without relying on native security (SROS2) being enabled—which is rarely seen in practice.

## Installation

```bash
# 1. Create a ROS 2 workspace and clone the repository
mkdir -p ros2_ws/src
cd ros2_ws/src
git clone https://github.com/seergiromero/ROS2-Intrusion-Detection.git
cd ..

# 2. Install dependencies automatically
rosdep install --from-paths src --ignore-src -r -y

# 3. Build and source the workspace
colcon build
source install/setup.bash
```
