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
  ```
* **Filter by Participant GUID Prefix:**
  ```text
  rtps.guidPrefix == 01:0f:a4:43:12:34:56:78:9a:bc:de:f0
  ```

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

# Phase 1: Automated RTPS Parsing & Real-Time Introspection

## 8. Overview & Tooling Architecture

While Phase 0 established manual inspection techniques via Wireshark, Phase 1 transitions to programmatic, real-time network introspection. The implementation consists of a lightweight socket-based sniffer (`rtps_sniffer.py`) and a zero-dependency binary protocol parser (`rtps_parser.py`), deliberately kept as separate concerns: the parser is a pure function of bytes in, events out — no state, no I/O, no logging — which is what makes it independently testable against captured traffic without needing a live network.

```text
+-------------------+      Raw UDP       +-------------------+      Event Stream     +----------------------+
|  AsyncSniffer      |  -------------->   |    RTPSParser      |  ----------------->   | RTPSSniffer state /  |
|  (scapy, bg thread)|   (Bytes Payload)  | (pure functions)   |   (Discovered/Disposed| callbacks -> future   |
+-------------------+                    +-------------------+        Events)        | Introspector node    |
                                                                                       +----------------------+
```

The system converts raw RTPS datagrams into structured Python `@dataclass` events:

* `ParticipantDiscovered`: SPDP announcements containing GUID prefixes, vendor ID, and lease duration.
* `EndpointDiscovered`: SEDP declarations of Publishers (`DATA(w)`) and Subscribers (`DATA(r)`) with topic names, data types, and QoS settings.
* `EntityDisposed`: teardown events marking a participant or endpoint withdrawal, carrying the specific GUID of the entity going away (never "the whole participant" unless it genuinely is the participant being disposed — see 9.2).

The current implementation uses a `networkx.MultiDiGraph`: participants and
topics are vertices, publisher endpoints create `participant -> topic` edges,
and subscriber endpoints create `topic -> participant` edges. The endpoint GUID
is the edge key, so repeated announcements update an existing endpoint instead
of creating duplicates while distinct endpoints sharing the same participant
and topic remain visible.

---

## 9. Real-World Protocol Discoveries & Parsing Logic

Building a custom RTPS parser revealed protocol behaviors that a purely theoretical reading of the spec would not have surfaced. Each claim below is tied to a specific verified capture — see 9.5 for the evidence table.

### 9.1 Dual-Region Parameter Structure: Inline QoS vs. Serialized Data Payload

A `DATA` submessage (`0x15`) can carry parameters in up to two distinct regions, each with different offset rules and encapsulation requirements. Both are governed by submessage flags, not by fixed byte offsets:

| Parameter Region | Trigger Flag | Offset Start | Encapsulation Header | Description |
| :--- | :--- | :--- | :--- | :--- |
| **Inline QoS** | `flags & 0x02` (`Q=1`) | `4 + octetsToInlineQos` | **None** | A raw `ParameterList` starting immediately at the computed offset, no PL_CDR wrapper. Parsed until `PID_SENTINEL`. |
| **Serialized Data Payload** | `flags & 0x04` (`D=1`) | *dynamic*: right after the inline QoS region if `Q=1`, otherwise byte 20 | **PL_CDR (4 bytes)** | Requires skipping a 4-byte encapsulation header (`0x00 0x03` = `PL_CDR_LE`, `0x00 0x02` = `PL_CDR_BE`) before the `ParameterList` begins. |

**Implementation note:** the current parser assumes the standard 16-byte
`octetsToInlineQos` value and therefore starts the fixed DATA payload at the
corresponding offsets (20 bytes into the DATA payload, followed by the 4-byte
PL_CDR encapsulation). It validates submessage lengths before slicing. A future
vendor-specific `octetsToInlineQos` value would require extending the parser
and adding a capture-based regression test; it is not currently claimed as
supported.

**Not yet verified with a real capture:** the case where `Q=1` and `D=1` are both set on the same submessage (inline QoS *and* main data together, e.g. a discovery announcement that also carries partition info). The parser's offset arithmetic is written to handle it, but every real capture collected so far has had `Q` and `D` as mutually exclusive.

### 9.2 Entity ID Classification (verified against real traffic)

Correct classification of a `DATA` submessage depends entirely on its `writerEntityId` — not on which PIDs happen to be present, which was an early mistake (a message containing `PID_PARTICIPANT_GUID` was briefly misclassified as SPDP, when in fact `PID_PARTICIPANT_GUID` also legitimately appears inside SEDP endpoint announcements as the owning participant's key).

| Constant | Value | Role | Verified by capture |
| :--- | :--- | :--- | :--- |
| `SPDP_WRITER_ENTITY_IDS` | `00:01:00:c2` | SPDP participant announcer | `spdp_participant_discovery` |
| — (same set, unused in practice) | `00:00:01:c1` | `ENTITYID_PARTICIPANT` — appears as the *suffix* of a participant's own GUID, never observed as a `writerEntityId` | n/a — kept defensively, matches nothing in practice |
| `SEDP_PUB_WRITER_ID` | `00:00:03:c2` | SEDP publications (`DATA(w)`) announcer | `sedp_publication_bond_status` |
| `SEDP_SUB_WRITER_ID` | `00:00:04:c2` | SEDP subscriptions (`DATA(r)`) announcer | `sedp_subscription_nav2_reply`, `sedp_subscription_dispose` |
| `SEDP_TOPIC_WRITER_ID` | `00:00:02:c2` | SEDP topics announcer | not yet captured — defined but not exercised by any test |

Any `writerEntityId` outside this set is currently treated as unclassified traffic and silently ignored (returns no event, does not raise). This is a deliberate choice — user-data writers (actual `/scan`, `/cmd_vel` message traffic, not discovery traffic) will also hit this path, and that's correct: the parser only models discovery/lifecycle events, not application data.

### 9.3 Lifecycle Teardown & Endpoint Disposal Mechanics

The initial assumption — that endpoint destruction is signaled by the Key flag (`K=1`) without Data (`D=0`) on the main `DATA` submessage — does not match what Fast DDS actually sends. A real captured dispose frame (a ROS2 subscription closing cleanly) had `flags = 0x03`: `E=1, Q=1, D=0, K=0`. **Neither D nor K was set.**

* **Verified disposal indicator:** a submessage signals dispose/unregister when `PID_STATUS_INFO` (`0x0071`) is present **inside the Inline QoS region** with a non-zero value. Per spec, the meaningful bits live in the last octet of the 4-byte value, in fixed wire order (not affected by the endianness flag): bit `0x01` = `DISPOSED`, bit `0x02` = `UNREGISTERED`. In the observed capture both were set (`0x03`) — a combined dispose+unregister, which is what Fast DDS sends when an endpoint is cleanly destroyed.
* **Target identification (verified path):** the disposed entity's own GUID is read from `PID_KEY_HASH` (`0x0070`) within that same Inline QoS block.
* **Speculative fallback path (not verified):** if `has_key` is set without `has_data` and *without* a `PID_STATUS_INFO` hit, the parser falls back to treating it as a bare-K-flag dispose and looks for `PID_ENDPOINT_GUID`/`PID_PARTICIPANT_GUID` in what would normally be the main `serializedData` region. This exists defensively for other DDS vendors that might not follow Fast DDS's inline-QoS convention — it has never been exercised against real traffic and should not be trusted as documented behavior until it is.
* **Participant-level dispose is inferred, not confirmed:** `is_participant` is set to `True` whenever the disposing writer is the SPDP announcer, by symmetry with the endpoint case. No real capture of a full participant teardown (e.g. an entire ROS2 process crashing or exiting) has been collected yet to confirm Fast DDS follows the same `PID_STATUS_INFO`-in-inline-QoS convention at that level.

### 9.4 Endianness Resolution

Endianness must be evaluated independently for the two regions described in 9.1:

1. **Submessage header, fixed fields, and Inline QoS:** governed entirely by bit 0 of the submessage flags (`0` = big-endian, `1` = little-endian). The Inline QoS region has no encapsulation header of its own, so this is the *only* source of truth for its endianness.
2. **Serialized Data Payload only:** its own 4-byte PL_CDR encapsulation header carries an independent endianness indicator (byte offset 1 within that header: `0x03` = LE, `0x02` = BE). In every capture collected so far this has always agreed with the submessage flag — a mismatch has never been observed — but the parser reads it independently rather than assuming agreement, since nothing in the spec guarantees it.

### 9.5 Verified Capture Evidence

| Capture name | Message type | What it confirmed |
| :--- | :--- | :--- |
| `spdp_participant_discovery` | `DATA(p)` | `SPDP_WRITER_ENTITY_IDS` classification; `ParticipantDiscovered` field extraction |
| `sedp_publication_bond_status` | `DATA(w)` | `SEDP_PUB_WRITER_ID`; `rt/` topic prefix normalization; QoS decoding |
| `sedp_subscription_nav2_reply` | `DATA(r)` | `SEDP_SUB_WRITER_ID`; the `rr/` action-reply prefix is normalized to `/` by the current parser |
| `sedp_subscription_dispose` | `DATA(w)[UD]` | The entire dispose/unregister mechanism in 9.3 — this is what corrected the original (wrong) K-flag-only assumption |

---

## 10. Sniffer Architecture & State Management (`rtps_sniffer.py`)

`RTPSSniffer` is the stateful layer that wraps the pure `RTPSParser`: it owns the live capture thread, the in-memory graph state, and the rules for how that state changes over time.

* **Capture:** `scapy.AsyncSniffer` running in a background thread, filtered to the DDS/RTPS UDP port range (`7400`–`7600`). Chosen over a plain `sniff()` call specifically because `AsyncSniffer.stop()` is real and immediate — a plain `sniff()` with a `stop_filter` only re-evaluates the moment the *next* packet arrives, which means it can hang indefinitely on a quiet network.
* **Thread safety:** all reads/writes to `discovered_participants` and `discovered_endpoints` go through a single `threading.Lock`. Callbacks (`on_update_callback`) are always invoked **outside** the lock, so a slow or misbehaving callback can't block packet processing.
* **Fault isolation:** every packet goes through `_process_packet`, wrapped in a `try/except` that logs and discards malformed input rather than propagating — a single corrupt or truncated frame must not kill the capture thread.
* **Liveness tracking (`_lease_reaper_loop`):** a second background thread periodically checks each known participant's `last_seen` timestamp against its advertised `leaseDuration` (read from `PID_PARTICIPANT_LEASE_DURATION`, defaulting to 20s if absent) and purges silent participants — along with their endpoints — once the lease expires. This is what makes the graph reflect nodes that crashed or lost network connectivity without a clean SPDP/dispose exchange, not just nodes that explicitly announced their departure.
* **Precise dispose handling:** this went through one real bug fix worth documenting as a design decision, not just a footnote. An earlier version purged *every* endpoint sharing a disposed message's `guid_prefix` — meaning a single legitimate dispose of one subscription could wipe out an entire node's worth of unrelated endpoints from the graph. The current version purges exactly the entity named in `EntityDisposed.disposed_guid`, and does **nothing** if that GUID could not be decoded, rather than guessing. This matters beyond correctness: a forged dispose message is a plausible attack vector against the graph itself (see Phase 2 planning — "graph poisoning"), and an over-eager purge policy would make that attack more powerful than it needs to be.

---

## 11. Diagnostic Logging & Event Verification

The sniffer's optional `debug=True` mode logs structured output designed to be cross-referenced directly against Wireshark's own field names, so a suspicious event can be manually verified frame-by-frame without guessing which packet it came from:

```text
[RTPS HEADER ] Version: 2.3 | Vendor ID: 0x010f | GUID Prefix: 01:0f:39:63:e3:0f:8a:c4:00:00:00:00
--------------------------------------------------------------------------------
  [SUBMSG #0] ID: 0x15 (DATA) | Flags: 0x03 (Endian: LE) | Len: 52B
    ├── [DATA SUBMSG] Reader: SEDP_BUILTIN_SUBSCRIPTIONS_DETECTOR | Writer: SEDP_BUILTIN_SUBSCRIPTIONS_ANNOUNCER | SeqNum: 532
    │   └── [DISPOSED / UNREGISTERED] StatusInfo: 0x00000003 | Target GUID: 01:0f:39:63:e3:0f:8a:c4:00:00:00:00:00:04:09:04
```

---

## 12. Test Suite Strategy

The suite (`pytest`, under `rids_introspector/test/`) is split by what it validates against, not just by file:

1. **Synthetic unit tests (`test_rtps_parser.py`):** hand-built RTPS byte sequences (via helpers in `rtps_fixtures.py` — `build_data_submessage`, `build_parameter_list`, etc.) that exercise specific code paths inconvenient to capture on demand: malformed/truncated input, unknown `writerEntityId` values, QoS parameter decoding, and the internal consistency of the dispose logic. These verify the parser is self-consistent, not that they match real DDS vendor behavior.
2. **Real-capture regression tests, parametrized (`REAL_CAPTURES` in `rtps_fixtures.py`):** each entry pairs a real Wireshark-exported hex payload with ground-truth values read directly off Wireshark's own decode — never computed from the parser itself. A single parametrized test iterates the list, so adding a new verified message type (e.g. a future ACKNACK or HEARTBEAT capture) requires no new test code, only a new fixture entry.
3. **Sniffer integration tests (`test_rtps_sniffer.py`):** exercise the full pipeline — real captured bytes wrapped in an in-memory scapy packet, through `_process_packet`, into internal state and callbacks — without needing root privileges or live traffic. Includes two regression tests written specifically against the over-purge bug fixed in Section 10: one confirms disposing a single endpoint leaves its sibling endpoints (same participant) untouched, another confirms an undecodable dispose GUID purges nothing rather than falling back to a broad guess. Lease expiration is tested by monkeypatching `time.sleep` to run exactly one reaper iteration deterministically, rather than sleeping in real time.

---

## 13. Known Limitations & Open Items

Documented here deliberately, rather than silently left for someone to rediscover:

* `Q=1` and `D=1` combined on the same submessage: offset arithmetic is implemented but has no real-capture test backing it yet.
* The bare-K-flag dispose fallback (9.3) has never matched real traffic — it may be dead code, or it may be exactly what a different DDS vendor needs. Unknown until tested against one.
* Participant-level dispose (`is_participant=True`) is inferred by symmetry with endpoint dispose, not confirmed against a real full-participant teardown capture.
* `SEDP_TOPIC_WRITER_ID` is defined but not currently used in classification logic, and has no verified capture.
* ROS2 action-layer topic prefixes `rq/` (request) and `rr/` (reply) are currently normalized to `/`, but this behavior has only been verified with the available capture set.
* No `eBPF`-based capture path exists (see Phase 0 evaluation) — the parser only ever sees traffic `AsyncSniffer`/`scapy` can observe from userspace, meaning an attacker who crafts raw RTPS packets bypassing the normal socket path in a way userspace capture can't see would not be detected. Documented as a scope boundary, not solved.