# DDS / RTPS Network Fundamentals & Traffic Analysis

## 1. Overview & Capture Setup

This document outlines the network introspection baseline conducted during Phase 0 of the RIDS project. The target environment consists of a simulated mobile robot (TurtleBot3 Waffle) running ROS 2 with Nav2 and Gazebo.

### Capture Environment
* **Target Interface:** `lo` (Loopback interface). Because all ROS 2 nodes, Gazebo, and Nav2 processes execute locally, communication bypasses physical network interfaces (`wlan0`/`eth0`) and routes through `127.0.0.1`.
* **Transport Layer:** UDP (User Datagram Protocol).
* **Wire Protocol:** RTPS (Real-Time Publish-Subscribe) version 2.x, managed by the underlying DDS middleware (e.g., eProsima FastDDS).

---

## 2. RTPS Protocol Architecture

ROS 2 does not send high-level node names or topic definitions directly over the wire. Instead, it relies on the OMG RTPS standard operating on top of UDP/IP:

`ROS 2 Topic Layer` $\rightarrow$ `RMW Layer` $\rightarrow$ `DDS Middleware` $\rightarrow$ `RTPS Submessages` $\rightarrow$ `UDP/IP`

### Main Traffic Categories

| Traffic Type | Submessage Type | Destination | Function |
| :--- | :--- | :--- | :--- |
| **Participant Discovery (SPDP)** | `DATA(p)` | Multicast (`239.255.0.1:7400`) | Announces participant (node process) presence and network endpoints. |
| **Endpoint Discovery (SEDP)** | `DATA(w)`, `DATA(r)` | Unicast | Declares Publishers (`DataWriter`) and Subscribers (`DataReader`). |
| **Session Control** | `HEARTBEAT`, `ACKNACK`, `GAP` | Unicast | Manages QoS reliability, sequence acknowledgments, and buffer gaps. |

---

## 3. Discovery Protocol Breakdown: SPDP vs. SEDP

Discovery in DDS is a multi-stage process where SPDP and SEDP run concurrently across the lifespan of the ROS 2 network execution.

```text
+---------------------------------------------------------------------------------+
|                                 SPDP (Multicast)                                |
|   Participant Discovery & Keep-Alive (Continuous periodic broadcasts: DATA(p))   |
+---------------------------------------------------------------------------------+
                                         |
                                         v (Participant Discovered)
+---------------------------------------------------------------------------------+
|                                 SEDP (Unicast)                                  |
|     Endpoint Discovery & QoS Match (Event-driven exchanges: DATA(w), DATA(r))   |
+---------------------------------------------------------------------------------+
```

### 3.1 SPDP (Simple Participant Discovery Protocol)
SPDP operates at the **Participant (Node Process) level**. Unlike a one-off handshake, SPDP remains active indefinitely to maintain network cohesion.

* **Transmission Mode:** Periodic Multicast to `239.255.0.1:7400`.
* **Core Functions:**
  * **Initial Announcement:** Notifies existing nodes when a new ROS 2 node boots up.
  * **Keep-Alive / Heartbeat Mechanism:** If a participant fails to broadcast `DATA(p)` within its designated `leaseDuration`, active nodes prune it from the network graph.
  * **Late-Joiner Support:** Ensures nodes initialized later in the execution cycle discover pre-existing network participants.
* **Key Header Fields:**
  * `guidPrefix`: A 12-byte unique identifier representing the host machine, process ID, and participant instance.
  * `vendorId`: Identifies the DDS vendor implementation (e.g., `01.0f` for eProsima FastDDS).
* **RIDS Security Relevance:** Any new process entering the graph—including rogue nodes—must announce itself via an initial `DATA(p)` packet. Monitoring SPDP provides the first line of defense against unauthorized participants.

### 3.2 SEDP (Simple Endpoint Discovery Protocol)
SEDP operates at the **Endpoint (Publisher / Subscriber) level** and executes strictly after two participants establish mutual discovery via SPDP.

* **Transmission Mode:** Direct Unicast (Point-to-Point) between discovered nodes.
* **Core Functions:**
  * Executed on demand whenever a ROS 2 node instantiates a `Publisher` or `Subscription`.
  * Exchanges metadata regarding topic channels, message structures, and QoS parameters to establish communication matching.
* **Submessage Types:**
  * `DATA(w)`: Published by a `DataWriter` to declare a topic publisher.
  * `DATA(r)`: Published by a `DataReader` to declare a topic subscriber.
* **Inspecting Parameters in Wireshark:**
  * Packet Path: `Real-Time Publish-Subscribe Wire Protocol` $\rightarrow$ `submessage: DATA(w)` (or `DATA(r)`) $\rightarrow$ `serializedData` $\rightarrow$ `parameterList`
* **Critical Parameter Identifiers (`PID`):**
  * `PID_TOPIC_NAME`: Name of the topic. *Note: ROS 2 prepends `rt/` to topic names at the DDS layer (e.g., `/cmd_vel` appears as `rt/cmd_vel`).*
  * `PID_TYPE_NAME`: Datatype definition (e.g., `geometry_msgs::msg::dds_::Twist_`).
  * `PID_RELIABILITY`: Reliability policy (`RELIABLE` vs. `BEST_EFFORT`).
  * `PID_DURABILITY`: Durability policy (`TRANSIENT_LOCAL` vs. `VOLATILE`).
* **RIDS Security Relevance:** SEDP packets expose topic-level unauthorized actions, such as a rogue node attempting to publish (`DATA(w)`) to velocity control topics (`rt/cmd_vel`) or eavesdrop (`DATA(r)`) on private sensor feeds.

---

## 4. GUID Anatomy & Cross-Layer Correlation

To bridge the gap between high-level ROS 2 CLI commands (`rclpy`/`rclcpp`) and low-level wire packets, security analysis relies on **Global Unique Identifiers (GUIDs)**.

### 4.1 GUID Structure
Every entity in a DDS network is uniquely identified by a 16-byte GUID, divided into two distinct parts:

```text
[                 guidPrefix (12 bytes)                 ] [ entityId (4 bytes) ]
01 : 0f : 39 : 63 : 92 : 9d : 24 : af : 00 : 00 : 00 : 00 : 00 : 03 : 5c : 03
|_________________________________________________________| |__________________|
          Identifies Node / Process (SPDP Level)            Identifies Endpoint
                                                            (Publisher/Subscriber)
```

1. **`guidPrefix` (12 Bytes):** Shared by all publishers, subscribers, and services created within the same ROS 2 node process. It is established during the SPDP exchange (`DATA(p)`).
2. **`entityId` (4 Bytes):** Distinguishes specific endpoints within that node. For instance, `XX.XX.XX.03` typically denotes a `DataWriter`, while `XX.XX.XX.04` denotes a `DataReader`.

### 4.2 Cross-Layer Verification: ROS 2 CLI vs. Wireshark Raw Packets

To verify network behavior during development, match high-level ROS 2 graph outputs with raw packet captures:

1. **Retrieve GUID via ROS 2 CLI:**
   ```bash
   ros2 topic info /cmd_vel -v
   ```
   *Output Example:*
   ```text
    Node name: ros_gz_bridge
    Node namespace: /
    Topic type: geometry_msgs/msg/TwistStamped
    Topic type hash: RIHS01_5f0fcd4f81d5d06ad9b4c4c63e3ea51b82d6ae4d0558f1d475229b1121db6f64
    Endpoint type: SUBSCRIPTION
    GID: 01.0f.39.63.8d.9d.81.dd.00.00.00.00.00.00.18.04
    QoS profile:
    Reliability: RELIABLE
    History (Depth): UNKNOWN
    Durability: VOLATILE
    Lifespan: Infinite
    Deadline: Infinite
    Liveliness: AUTOMATIC
    Liveliness lease duration: Infinite
   ```

2. **Locate the GUID in Wireshark:**
   * **Formatting Note:** ROS 2 separates bytes with dots (`.`), whereas Wireshark requires colons (`:`).
   * **Filter by Node (`guidPrefix`):**
     ```text
     rtps.guidPrefix == 01:0f:a4:43:12:34:56:78:9a:bc:de:f0
     ```
   * **Filter by Endpoint (`guid`):**
     ```text
     rtps.guid == 01:0f:a4:43:12:34:56:78:9a:bc:de:f0:00:00:03:02
     ```
   * **Direct Hex Search (`Ctrl + F`):** In Wireshark, press `Ctrl + F`, set search criteria to `Packet details` and `Hex value`, then search for the continuous hex string: `010fa443123456789abcdef000000302`.

---

## 5. Data Transfer & Flow Control

### User Data (`DATA` / `DATA_FRAG`)
* **`DATA`**: Encapsulates actual ROS 2 message payloads (e.g., odometry updates, velocity commands).

### Control Submessages
* **`HEARTBEAT`**: Issued by a `DataWriter` to inform `DataReaders` of available sequence numbers.
* **`ACKNACK`**: Sent by a `DataReader` to confirm receipt of sequences or request retransmission of missing packages.
* **`GAP`**: Issued by a `DataWriter` to instruct readers to skip sequences that are no longer available.
* **`INFO_TS` (InfoTimestamp)**: Provides a high-resolution timestamp for subsequent submessages in the same RTPS packet, establishing exact generation or transmission time for time-sensitive payloads.
* **`INFO_DST` (InfoDestination)**: Specifies the target participant (`guidPrefix`) intended to receive subsequent submessages, enabling explicit unicast/multicast destination routing.

---

## 6. Wireshark Inspection Strategy & Display Filters

Use the following display filters in Wireshark to isolate DDS traffic from system noise (such as X11, Docker TCP streams, or HTTP traffic):

* **Isolate all RTPS traffic over UDP:**
  ```text
  rtps && udp
  ```
* **Filter by standard DDS UDP ports:**
  ```text
  udp.port >= 7400
  ```
* **Locate specific topic discovery (e.g., `/cmd_vel`):**
  ```text
  rtps.param.topicName == "rt/cmd_vel"
  ```
* **Filter for user data submessages only:**
  ```text
  rtps.sm.id == 0x15
  ``
* **Filter by Participant GUID Prefix:**
  ```text
  rtps.guidPrefix == 01:0f:a4:43:12:34:56:78:9a:bc:de:f0
  ``

---

## 7. System Auditing with `ros2 doctor`

`ros2 doctor` serves as the primary CLI tool for auditing system health, RMW configurations, and network settings prior to packet capture analysis.

* **Run basic check:**
  ```bash
  ros2 doctor
  ```
* **Generate full system report:**
  ```bash
  ros2 doctor --report
  ```

---