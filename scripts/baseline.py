#!/usr/bin/env python3
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

RIDS baseline capture tool.

Captures live RTPS discovery traffic from a normally-operating ROS 2 system and
writes a ``baseline.yaml`` file consumable by ``rids_detector``.

The system under monitor must already be running (e.g. ``talker/listener`` or a
full Nav2 + TurtleBot3 stack). While it runs, execute this tool to "learn" the
normal DDS communication graph: every participant (a ROS 2 node process) and
every endpoint (a publisher or subscriber writer/reader) is recorded.

Run order (recommended):
    1. In one terminal, with the workspace sourced, start the capture FIRST:
           python scripts/baseline.py --source nav2_normal_run \\
               --critical-topic /cmd_vel --critical-topic /scan \\
               --critical-topic /goal_pose --critical-topic /tf
    2. In another terminal, launch the ROS 2 system:
           ros2 launch <your_package> <your_launch>.py
    3. Wait for the script to exit. Edit the generated YAML to curate
       ``critical_topics`` and ``source``.
    4. Start ``rids_detector`` against the produced baseline.

Run order (if the ROS 2 system is already running):
    RTPS SEDP — the protocol that announces publishers and subscribers — is
    broadcast exactly ONCE per application, at startup. A passive sniffer
    cannot ask an already-running node to re-announce; it can only wait for
    the next lease-driven retransmission (~20s after the node boots).
    The recommended workaround is to force rediscovery with:
        ros2 daemon stop; ros2 daemon start
    and then run this script. The daemon restart causes every participant
    to re-announce SPDP and SEDP, which the sniffer picks up cleanly.
    The ``--endpoint-warmup`` flag (default 20s) extends the capture window
    to catch lease-driven retransmissions, but ``ros2 daemon stop/start`` is
    the more reliable option when you cannot restart the ROS 2 system.

The tool starts a *passive* sniffer (no traffic is injected), waits for the DDS
discovery graph to settle (with an extended warmup window for SEDP
retransmissions), then converts the captured state into the validated baseline
schema defined by ``rids_detector.models``.
"""

from __future__ import annotations

import argparse
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import yaml


# ---------------------------------------------------------------------------
# Dependency resolution
# ---------------------------------------------------------------------------

def _ensure_workspace_on_path() -> None:
    """Add the in-tree packages to ``sys.path`` when running from source.

    When the workspace has been ``colcon build`` + ``source install/setup.bash``,
    the packages are already installed and this is a no-op. When running the
    script directly from the source tree without sourcing, we add the two ROS
    package directories so ``rids_introspector`` and ``rids_detector`` are
    importable as Python packages.
    """
    ws_root = Path(__file__).resolve().parent.parent
    candidate_paths = [
        ws_root / "rids_introspector",
        ws_root / "rids_detector",
    ]
    for candidate in candidate_paths:
        if candidate.is_dir():
            sys.path.insert(0, str(candidate))


def _import_deps() -> tuple[Any, Any, Any, Any]:
    """Lazy-import the classes that power capture and validation."""
    try:
        from rids_introspector.rtps_sniffer import RTPSSniffer
    except ImportError as exc:
        _fail_import("rids_introspector", exc)
    try:
        from rids_detector.baseline import BaselineLoader
        from rids_detector.models import Baseline, BaselineEndpoint
    except ImportError as exc:
        _fail_import("rids_detector", exc)
    return RTPSSniffer, BaselineLoader, Baseline, BaselineEndpoint


def _fail_import(name: str, exc: Exception) -> None:
    print(f"[baseline] Error: could not import '{name}'.", file=sys.stderr)
    print(f"  {exc}", file=sys.stderr)
    print("  Hint: source your ROS 2 workspace first, e.g.:", file=sys.stderr)
    print("    source install/setup.bash", file=sys.stderr)
    sys.exit(1)


# ---------------------------------------------------------------------------
# Capture logic
# ---------------------------------------------------------------------------

class BaselineCaptureError(RuntimeError):
    """Raised when capture completes but yields no usable graph state."""


def _kick_dds_discovery(warmup: float = 4.0) -> None:
    """Force already-running DDS participants to re-run SEDP against us.

    RTPS SEDP (the sub-protocol that announces publishers/subscribers) is
    only exchanged between a *pair* of participants the first time they are
    matched. A passive sniffer never becomes a real participant, so it is
    never "new" to anyone and never triggers that exchange.

    This spins up a throwaway ``rclpy`` node — a real, ephemeral DDS
    participant. As soon as it appears, every existing participant on the
    domain discovers it via SPDP and, because this is a *new* pairing for
    them, sends it a fresh SEDP burst describing all of their writers and
    readers. Our passive sniffer, listening on the same interface, captures
    that traffic exactly as if the nodes had just booted.

    The node is destroyed again immediately after the warmup window, which
    emits a participant DISPOSE that the sniffer's own EntityDisposed
    handling already knows how to clean up, so it leaves no trace in the
    captured state.
    """
    try:
        import rclpy
    except ImportError:
        print(
            "[baseline] rclpy not importable; skipping active discovery kick "
            "(source your ROS 2 workspace to enable this). Falling back to "
            "passive lease-driven capture only.",
            file=sys.stderr,
        )
        return

    print(
        f"[baseline] Kicking DDS discovery with a temporary participant "
        f"(warmup {warmup:.1f}s) ...",
        file=sys.stderr,
    )
    rclpy.init(args=[])
    node = rclpy.create_node("_rids_baseline_discovery_kicker")
    try:
        end = time.monotonic() + warmup
        while time.monotonic() < end:
            rclpy.spin_once(node, timeout_sec=0.1)
    finally:
        node.destroy_node()
        rclpy.shutdown()


def capture_graph(
    sniffer_cls: type,
    interface: str,
    port_filter: str | None,
    poll_interval: float,
    settle_time: float,
    max_duration: float,
    endpoint_warmup: float = 20.0,
    active_kick: bool = True,
    kick_warmup: float = 4.0,
) -> dict[str, Any]:
    """Start a passive RTPS sniffer and wait until the graph stabilises.

    The capture ends when, after at least one discovery has been observed, the
    participant/endpoint counts remain constant for ``settle_time`` seconds, or
    when ``max_duration`` is reached (whichever comes first).

    If participants are seen but no endpoints, the settle-time check is
    suppressed for ``endpoint_warmup`` seconds after the first participant
    arrived. This compensates for RTPS SEDP's "announce-once" behaviour: when
    a DDS application boots *before* the sniffer, the SEDP unicast burst
    announcing its publishers and subscribers has already gone by the time
    we start capturing, and the sniffer has no way to ask the application
    to re-announce until its lease expires (typically ~20 s). See the
    ``--endpoint-warmup`` flag for the operator override.

    Returns the raw ``get_captured_state()`` dictionary.
    """
    sniffer = sniffer_cls(
        interface=interface,
        port_filter=port_filter or None,
        debug=False,
    )
    sniffer.start()
    print(
        f"[baseline] Listening on interface '{interface}' "
        f"(filter: {port_filter or 'disabled'}).",
        file=sys.stderr,
    )
    if active_kick:
        # Force already-running nodes to re-announce their endpoints to us,
        # instead of waiting on the ~20s passive lease retransmission (or
        # requiring the operator to restart the ros2 daemon).
        _kick_dds_discovery(warmup=kick_warmup)

    print("[baseline] Waiting for the DDS discovery graph to settle ...",
          file=sys.stderr)

    start = time.monotonic()
    prev_signature: tuple[tuple[str, ...], tuple[tuple[str, str, str, str], ...]] | None = None
    stable_for = 0.0
    seen_anything = False
    seen_participants = False
    endpoint_warn_emitted = False
    endpoint_warmup_notice_emitted = False
    # Warn when participants show up but no endpoints do, *before* the
    # settle-time check has a chance to cut the capture short.  Using
    # settle_time / 2 keeps the warning visible while still being long
    # enough to filter out the first-second SPDP-only window that always
    # precedes SEDP announcements.
    endpoint_warn_delay = max(settle_time * 0.5, 2.0)
    # Track when the first participant was observed, so we know how long we
    # have been waiting for the matching SEDP burst.  If SEDP never arrives,
    # we still want to give it `endpoint_warmup` seconds before cutting.
    first_participant_at: float | None = None
    state: dict[str, Any] = {"participants": {}, "endpoints": {}}

    try:
        while True:
            time.sleep(poll_interval)
            state = sniffer.get_captured_state()
            participants = state.get("participants", {})
            endpoints = state.get("endpoints", {})
            participant_ids = tuple(sorted(str(guid) for guid in participants))
            endpoint_ids = tuple(
                sorted(
                    (
                        str(guid),
                        str(endpoint.get("guid_prefix", endpoint.get("participant", ""))),
                        str(endpoint.get("topic", "")),
                        str(endpoint.get("role", "")),
                    )
                    for guid, endpoint in endpoints.items()
                    if isinstance(endpoint, dict)
                )
            )
            signature = (participant_ids, endpoint_ids)
            n_participants = len(participant_ids)
            n_endpoints = len(endpoint_ids)

            if n_participants > 0 or n_endpoints > 0:
                seen_anything = True
            if n_participants > 0:
                if not seen_participants:
                    seen_participants = True
                    first_participant_at = time.monotonic() - start

            if seen_anything and signature == prev_signature:
                stable_for += poll_interval
            elif seen_anything:
                stable_for = 0.0
            # While nothing has been seen yet, keep waiting without counting.
            prev_signature = signature

            elapsed = time.monotonic() - start
            _render_progress(n_participants, n_endpoints, elapsed)

            if (
                not endpoint_warn_emitted
                and seen_anything
                and n_participants > 0
                and n_endpoints == 0
                and elapsed >= endpoint_warn_delay
            ):
                sys.stderr.write(
                    "\n  [!] %d participant(s) seen but 0 endpoints after %.1fs. "
                    "SEDP unicast traffic is likely being filtered out by "
                    "--port-filter, or the publisher/subscriber has not yet "
                    "been discovered.\n"
                    "      Suggested fixes:\n"
                    "        - Re-run with --port-filter \"\"  (no filter, "
                    "captures SEDP on dynamic ports).\n"
                    "        - Or widen the range, e.g. "
                    "--port-filter \"udp portrange 7400-7600 or udp dst portrange 7400-65535\".\n"
                    "        - Or extend --max-duration to give SEDP more time."
                    % (n_participants, elapsed)
                )
                sys.stderr.write("\n")
                sys.stderr.flush()
                endpoint_warn_emitted = True

            # Suppress the settle-time exit while we are still inside the
            # forced warmup window.  This is what gives the script a chance
            # to catch SEDP bursts from already-running ROS 2 nodes that
            # were started *before* the sniffer came up.
            warmup_elapsed = (
                elapsed - first_participant_at if first_participant_at is not None else 0.0
            )
            in_warmup = (
                seen_participants
                and n_endpoints == 0
                and warmup_elapsed < endpoint_warmup
            )

            if (
                not endpoint_warmup_notice_emitted
                and seen_participants
                and n_endpoints == 0
                and warmup_elapsed >= 2.0
                and endpoint_warmup > 0
            ):
                remaining = max(endpoint_warmup - warmup_elapsed, 0.0)
                sys.stderr.write(
                    "\n  [i] Holding capture for up to %.0fs more to allow "
                    "SEDP retransmissions from already-running DDS nodes "
                    "(RTPS SEDP is announced once at startup; we need to wait "
                    "for the lease to expire before nodes re-announce). "
                    "Set --endpoint-warmup 0 to disable.\n"
                    % remaining
                )
                sys.stderr.flush()
                endpoint_warmup_notice_emitted = True

            if seen_anything and stable_for >= settle_time and not in_warmup:
                break
            if elapsed >= max_duration:
                break
    finally:
        sniffer.stop()
        # The sniffer stops its background capture thread; clear the progress line.
        sys.stderr.write("\n")
        sys.stderr.flush()

    if not seen_anything:
        raise BaselineCaptureError(
            "No participants or endpoints were discovered during capture.\n"
            "Check that:\n"
            "  - Your ROS 2 system is actually running and publishing.\n"
            "  - The interface matches the one used by DDS (default 'lo').\n"
            "  - The port filter covers your DDS traffic "
            "(default 'udp portrange 7400-7600').\n"
            "  - You have permission to capture on the interface (try sudo / "
            "setcap for non-loopback interfaces)."
        )

    return state


def _render_progress(n_participants: int, n_endpoints: int, elapsed: float) -> None:
    sys.stderr.write(
        f"\r[baseline] participants={n_participants:<4} "
        f"endpoints={n_endpoints:<4} elapsed={elapsed:5.1f}s"
    )
    sys.stderr.flush()


# ---------------------------------------------------------------------------
# Baseline construction
# ---------------------------------------------------------------------------

def build_baseline(
    source: str,
    version: int,
    critical_topics: list[str],
    state: dict[str, Any],
) -> dict[str, Any]:
    """Convert the captured sniffer state into the baseline YAML schema."""
    participants_raw = state.get("participants", {})
    endpoints_raw = state.get("endpoints", {})

    # DDS/rmw-internal plumbing topics. These never go through the ROS 2
    # topic-name mangling convention ("rt/<name>", "rr/<name>", "rq/<name>")
    # that rtps_parser.py strips to recover the leading '/', because they
    # are not application topics at all — e.g. "ros_discovery_info" is
    # emitted by every rclpy/rclcpp node to propagate the ROS graph cache
    # (which node owns which topic) over plain DDS. They carry no signal
    # for intrusion detection and would otherwise fail BaselineEndpoint's
    # '/'-prefixed topic validation. Skip them explicitly, and defensively
    # skip anything else that doesn't start with '/' for the same reason.
    _NON_ROS_TOPICS = {"ros_discovery_info"}

    participant_guids: set[str] = set()
    if isinstance(participants_raw, dict):
        participant_guids.update(participants_raw.keys())
    elif isinstance(participants_raw, list):
        participant_guids.update(str(p) for p in participants_raw)

    endpoints: list[dict[str, Any]] = []
    for guid, ep in endpoints_raw.items():
        if not isinstance(ep, dict):
            continue
        guid_str = str(guid).strip()
        if not guid_str:
            continue

        participant = (
            ep.get("guid_prefix")
            or ep.get("participant")
        )
        if not participant:
            continue
        participant = str(participant).strip()
        participant_guids.add(participant)

        topic = (ep.get("topic") or "").strip()
        if not topic:
            # Topics always start with '/' in the parsed wire data; guard anyway.
            continue
        if topic in _NON_ROS_TOPICS or not topic.startswith("/"):
            # Middleware-internal plumbing (e.g. the rmw ROS-graph-cache
            # topic), not part of the application's actual pub/sub graph.
            continue

        type_name = (ep.get("type") or ep.get("type_name") or "").strip()
        if not type_name:
            continue
        role_raw = str(ep.get("role", "")).strip().lower()
        if role_raw in ("publisher", "writer"):
            role = "publisher"
        elif role_raw in ("subscriber", "reader"):
            role = "subscriber"
        else:
            # Muestra un aviso en debug si se descarta algo imprevisto
            continue

        qos = ep.get("qos", {}) or {}
        # Normalise QoS values to strings so the loader's validation passes.
        qos = {str(k).strip(): str(v).strip() for k, v in qos.items() if k and v}

        endpoints.append(
            {
                "guid": guid_str,
                "participant": participant,
                "topic": topic,
                "role": role,
                "type_name": type_name,
                "qos": qos,
            }
        )

    # Sort for deterministic, reviewable output.
    endpoints.sort(key=lambda e: (e["participant"] or "", e["guid"]))

    critical_topics_clean = [t.strip() for t in critical_topics if t and t.strip()]

    return {
        "version": version,
        "created_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "source": source,
        "critical_topics": critical_topics_clean,
        "participants": sorted(participant_guids),
        "endpoints": endpoints,
    }


def validate_baseline(data: dict[str, Any], loader_cls: Any) -> None:
    """Run the same validation the detector uses before we trust the file."""
    loader_cls().from_dict(data)


# ---------------------------------------------------------------------------
# Output
# ---------------------------------------------------------------------------

def write_baseline(data: dict[str, Any], output_path: Path) -> None:
    output_path.parent.mkdir(parents=True, exist_ok=True)
    with output_path.open("w", encoding="utf-8") as stream:
        yaml.safe_dump(data, stream, sort_keys=False, default_flow_style=False)


def print_summary(data: dict[str, Any], output_path: Path) -> None:
    participants = data["participants"]
    endpoints = data["endpoints"]
    topics = sorted({ep["topic"] for ep in endpoints})

    pubs = sum(1 for ep in endpoints if ep["role"] == "publisher")
    subs = sum(1 for ep in endpoints if ep["role"] == "subscriber")

    print(f"[baseline] Capture complete:", file=sys.stderr)
    print(f"  baseline version : {data['version']}", file=sys.stderr)
    print(f"  source           : {data['source']}", file=sys.stderr)
    print(f"  created_at       : {data['created_at']}", file=sys.stderr)
    print(f"  participants     : {len(participants)}", file=sys.stderr)
    print(f"  endpoints        : {len(endpoints)} ({pubs} publisher, {subs} subscriber)", file=sys.stderr)
    print(f"  topics           : {len(topics)}", file=sys.stderr)
    print(f"  critical_topics  : {len(data['critical_topics'])}", file=sys.stderr)
    print(f"  output           : {output_path}", file=sys.stderr)

    if not data["critical_topics"]:
        print(
            "\n  [!] 'critical_topics' is empty. Edit the YAML and add the "
            "topics\n  that are security-sensitive for your system (e.g. "
            "/cmd_vel, /scan).\n  The detector relies on this list to flag "
            "unauthorized publishers.",
            file=sys.stderr,
        )

    if not data["endpoints"] and data["participants"]:
        print(
            "\n  [!] WARNING: 0 endpoints captured but %d participants were.\n"
            "      The baseline will flag every existing publisher and subscriber\n"
            "      as 'new' at runtime, which is almost certainly wrong.\n"
            "\n"
            "      Why this happens: RTPS SEDP (the protocol that announces\n"
            "      publishers and subscribers) is sent ONCE at startup by every\n"
            "      DDS application. A passive sniffer cannot ask an already-running\n"
            "      node to re-announce; it can only wait for the next lease-driven\n"
            "      retransmission (~20s after the node boots).\n"
            "\n"
            "      Recommended workflow to fix this:\n"
            "        1. Easiest — start the script BEFORE the ROS 2 system.\n"
            "             Terminal 1:  python3 scripts/baseline.py --source ...\n"
            "             Terminal 2:  ros2 run demo_nodes_cpp talker\n"
            "             Terminal 3:  ros2 run demo_nodes_cpp listener\n"
            "        2. If the system is already running, force rediscovery:\n"
            "             ros2 daemon stop; ros2 daemon start\n"
            "           then re-run this script (the daemon restart triggers every\n"
            "           participant to re-announce SPDP and SEDP).\n"
            "        3. Or, more invasive: kill and relaunch the ROS 2 nodes.\n"
            "        4. As a last resort, the script's --endpoint-warmup (default\n"
            "           20s) extends the capture window to catch the next lease\n"
            "           renewal. Use --endpoint-warmup 60 if your nodes lease slowly.\n"
            "\n"
            "      Other possible causes (less likely once endpoints are 0):\n"
            "        - The --port-filter blocked SEDP unicast traffic. Re-run with\n"
            "          --port-filter \"\"  (no filter) to capture SEDP on dynamic\n"
            "          ports outside the 7400-7600 default range.\n"
            "        - Capture permissions are insufficient (try sudo for non-loopback\n"
            "          interfaces, or setcap cap_net_raw+ep on the python interpreter)."
            % len(data["participants"]),
            file=sys.stderr,
        )


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        prog="baseline",
        description=(
            "Capture a live ROS 2 RTPS discovery graph and write a baseline "
            "YAML file for rids_detector."
        ),
    )
    parser.add_argument(
        "--source",
        default=None,
        help=(
            "Descriptive name for this baseline (e.g. 'nav2_normal_run'). "
            "Defaults to 'auto_<timestamp>'."
        ),
    )
    parser.add_argument(
        "--version",
        type=int,
        default=1,
        help="Schema version to write into the baseline (default: 1).",
    )
    parser.add_argument(
        "-o", "--output",
        default="config/baseline.yaml",
        help="Output baseline YAML path (default: config/baseline.yaml).",
    )
    parser.add_argument(
        "--critical-topic",
        action="append",
        default=[],
        metavar="TOPIC",
        help=(
            "Mark a topic as critical for intrusion detection. Repeatable. "
            "Topics must start with '/'. If omitted, the list is left empty "
            "for manual editing afterwards."
        ),
    )
    parser.add_argument(
        "--interface",
        default="lo",
        help="Network interface to capture RTPS traffic on (default: lo).",
    )
    parser.add_argument(
        "--port-filter",
        default="udp portrange 7400-7600",
        help="BPF capture filter (default: udp portrange 7400-7600). Use '' to disable.",
    )
    parser.add_argument(
        "--poll-interval",
        type=float,
        default=1.0,
        help="How often to sample the sniffer state while waiting for settle (default: 1.0s).",
    )
    parser.add_argument(
        "--settle-time",
        type=float,
        default=3.0,
        help="Seconds of stable discovery counts required before stopping (default: 3.0s).",
    )
    parser.add_argument(
        "--max-duration",
        type=float,
        default=30.0,
        help="Hard timeout for the capture in seconds (default: 30.0s).",
    )
    parser.add_argument(
        "--endpoint-warmup",
        type=float,
        default=20.0,
        help=(
            "Seconds to keep capturing after the first participant is seen, "
            "even if the discovery graph looks 'stable', to give already-running "
            "DDS nodes a chance to re-announce their endpoints on lease "
            "expiration. Set to 0 to disable. Default: 20s (covers a typical "
            "DDS lease_duration of ~20s)."
        ),
    )
    parser.add_argument(
        "--active-kick",
        dest="active_kick",
        action="store_true",
        default=True,
        help=(
            "Spin up a temporary rclpy participant right after the sniffer "
            "starts, to force already-running DDS nodes to re-run SEDP "
            "endpoint discovery against it (default: enabled). This is what "
            "actually solves capturing endpoints when baseline.py is started "
            "AFTER the ROS 2 system, without touching the ros2 daemon."
        ),
    )
    parser.add_argument(
        "--no-active-kick",
        dest="active_kick",
        action="store_false",
        help="Disable the active discovery kick; fall back to purely passive capture.",
    )
    parser.add_argument(
        "--kick-warmup",
        type=float,
        default=4.0,
        help=(
            "Seconds to keep the temporary discovery-kick participant alive "
            "before tearing it down (default: 4.0s). Increase slightly on "
            "busy networks if endpoints are still missed."
        ),
    )
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    _ensure_workspace_on_path()
    args = parse_args(argv)

    source = args.source or f"auto_{datetime.now(timezone.utc).strftime('%Y%m%d_%H%M%S')}"
    print(f"[baseline] source='{source}'  version={args.version}", file=sys.stderr)

    if args.poll_interval <= 0:
        print("[baseline] Error: --poll-interval must be > 0.", file=sys.stderr)
        return 2
    if args.settle_time <= 0:
        print("[baseline] Error: --settle-time must be > 0.", file=sys.stderr)
        return 2
    if args.endpoint_warmup < 0:
        print("[baseline] Error: --endpoint-warmup must be >= 0.", file=sys.stderr)
        return 2
    if args.max_duration <= args.settle_time:
        print(
            "[baseline] Error: --max-duration must be greater than --settle-time.",
            file=sys.stderr,
        )
        return 2

    for topic in args.critical_topic:
        if not topic.startswith("/"):
            print(
                f"[baseline] Error: critical topic '{topic}' must start with '/'.",
                file=sys.stderr,
            )
            return 2

    RTPSSniffer, BaselineLoader, _Baseline, _BaselineEndpoint = _import_deps()

    try:
        state = capture_graph(
            sniffer_cls=RTPSSniffer,
            interface=args.interface,
            port_filter=args.port_filter,
            poll_interval=args.poll_interval,
            settle_time=args.settle_time,
            max_duration=args.max_duration,
            endpoint_warmup=args.endpoint_warmup,
            active_kick=args.active_kick,
            kick_warmup=args.kick_warmup,
        )
    except BaselineCaptureError as exc:
        print(f"[baseline] {exc}", file=sys.stderr)
        return 1

    baseline_data = build_baseline(
        source=source,
        version=args.version,
        critical_topics=args.critical_topic,
        state=state,
    )

    try:
        validate_baseline(baseline_data, BaselineLoader)
    except Exception as exc:  # noqa: BLE001 — surface any validation error cleanly
        print(
            f"[baseline] Generated baseline failed validation: {exc}",
            file=sys.stderr,
        )
        return 1

    output_path = Path(args.output)
    if not output_path.is_absolute():
        output_path = (Path(__file__).resolve().parent.parent / output_path)
    write_baseline(baseline_data, output_path)
    print_summary(baseline_data, output_path)
    return 0


if __name__ == "__main__":
    sys.exit(main())