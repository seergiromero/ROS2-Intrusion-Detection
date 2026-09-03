# RIDS — ROS2 Network Intrusion Detection System

🚧 **Work in progress.** This README will be expanded as the project phases advance.

## Overview

Intrusion detection system for the ROS2/DDS communication graph of a mobile robot.
It monitors normal system traffic, learns a behavioral baseline, and detects anomalous 
activity (rogue nodes, unauthorized publishers, floods) using a combination of deterministic 
rules and an anomaly detection model.

## Current Status

- [x] Phase 0 — Simulation environment (TurtleBot3 Waffle + Nav2)
- [x] Phase 1 — RTPS graph visibility (`rids_introspector`)
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

## Phase 1: RTPS Introspector

The `rids_introspector` package observes RTPS discovery traffic passively and
reconstructs a live DDS communication graph. It currently focuses on the
SPDP/SEDP subset needed to identify participants, publishers, subscribers,
topics, message types, and selected QoS policies.

The implementation is intentionally split into small components:

```text
Scapy AsyncSniffer -> RTPSParser -> RTPSSniffer -> GraphBuilder
                                      |                |
                                      v                +-> snapshots JSONL
                               lifecycle state         +-> terminal / Matplotlib
```

The graph uses participants and topics as vertices. Publisher endpoints are
represented as `participant -> topic` edges; subscriber endpoints as
`topic -> participant` edges. Each endpoint edge keeps its GUID, role, type,
QoS, and last-seen timestamp. Multiple endpoints are preserved with a
`networkx.MultiDiGraph`.

### Running directly

The monitor is a regular Python process launched through the ROS 2 package,
not an `rclpy` node. It therefore uses normal command-line arguments:

```bash
ros2 run rids_introspector introspector_node \
  --interface lo \
  --log-file results/phase1/snapshots.jsonl \
  --table-width 180
```

By default it shows a terminal table and appends one JSON object per line to
the snapshot file. Stop it with `Ctrl+C`; capture and logging are stopped in
the cleanup path.

Useful options:

```text
--interface IFACE       Interface to capture, default: lo
--port-filter FILTER    BPF filter, default: udp portrange 7400-7600
--port-filter ""        Disable the BPF filter
--interval SECONDS      Snapshot and display interval, default: 1.0
--table-width COLUMNS   Terminal table width, default: 150
--gui                   Use the live Matplotlib graph
--no-terminal            Disable terminal output
--debug                 Enable parser and sniffer diagnostics
```

Examples:

```bash
# Terminal view with a wider table
ros2 run rids_introspector introspector_node --table-width 220

# Only capture and write JSONL
ros2 run rids_introspector introspector_node --no-terminal

# Matplotlib view
ros2 run rids_introspector introspector_node --gui
```

### Running with launch

The launch file passes arguments to the regular `argparse` process using
`ExecuteProcess`:

```bash
ros2 launch rids_introspector rids_introspector.launch.py \
  interface:=lo \
  interval:=1.0 \
  table_width:=180 \
  log_file:=results/phase1/snapshots.jsonl
```

For raw packet capture, Scapy may require root privileges or suitable Linux
capabilities. The required permission depends on the distribution and local
security policy; verify it before running the monitor on a non-loopback
interface. The default capture filter covers ports `7400-7600`, which is
appropriate for the tested local domain but should be adjusted for other DDS
domain or network configurations.

### Snapshot format

Snapshots are JSON Lines. The logger opens the file in append mode and creates
parent directories automatically:

```json
{"snapshot_id": 0, "timestamp": 1756890000.0, "datetime": "2025-09-03T...Z", "graph": {"stats": {"num_participants": 1, "num_topics": 1, "num_edges": 1}, "nodes": [], "edges": []}}
```

The exact graph contents depend on the traffic observed. Each edge includes a
stable endpoint GUID as its `key`, together with `role`, `qos`, `type_name`,
and `last_seen`.

### Scope and limitations

This is a practical RTPS discovery monitor, not a complete RTPS dissector. It
currently parses `DATA` submessages for SPDP, SEDP publications, and SEDP
subscriptions, plus the tested lifecycle disposal path. User-data payloads,
all RTPS control submessages, every DDS vendor encoding, and all QoS policies
are outside the current scope.

An attacker that injects UDP/RTPS data without registering as a normal DDS
participant may not appear in this discovery-based graph. Kernel-level eBPF
inspection is a possible future direction, but is deliberately outside the
scope of this phase.

### Tests

Run the package tests from the package directory:

```bash
cd ros2_ws/src/ROS2-Intrusion-Detection/rids_introspector
pytest -q
```

The tests cover synthetic malformed packets, real Wireshark capture fixtures,
publisher/subscriber graph construction, endpoint lifecycle, lease expiry,
JSONL snapshots, terminal rendering, sniffer lifecycle, and the integrated
RTPS-to-graph path without requiring live capture privileges.
