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

import argparse
import signal
import threading

from rids_introspector.graph_builder import GraphBuilder
from rids_introspector.graph_visualizer import GraphVisualizer
from rids_introspector.rtps_sniffer import RTPSSniffer
from rids_introspector.snapshot_logger import SnapshotLogger
from rids_introspector.terminal_visualizer import TerminalVisualizer


def parse_bool(value: str | bool) -> bool:
    if isinstance(value, bool):
        return value
    normalized = value.lower()
    if normalized in {"true", "1", "yes", "on"}:
        return True
    if normalized in {"false", "0", "no", "off"}:
        return False
    raise argparse.ArgumentTypeError(f"Invalid boolean value: {value}")


def main():
    parser = argparse.ArgumentParser(description="RIDS Network Introspector")
    parser.add_argument("--interface", default="lo", help="Network interface (default: lo)")
    parser.add_argument("--port-filter", default="udp portrange 7400-7600", help="BPF capture filter; use '' to disable")
    parser.add_argument("--debug", nargs="?", const=True, default=False, type=parse_bool, help="Enable debug logging")
    parser.add_argument("--gui", nargs="?", const=True, default=False, type=parse_bool, help="Enable live Matplotlib graph")
    parser.add_argument("--no-terminal", nargs="?", const=True, default=False, type=parse_bool, help="Disable terminal visualization")
    parser.add_argument("--log-file", default="snapshots.jsonl", help="Output path for snapshots")
    parser.add_argument("--interval", type=float, default=1.0, help="Snapshot interval in seconds (default: 1.0)")
    parser.add_argument("--table-width", type=int, default=150, help="Terminal table width in characters (default: 150)")
    args = parser.parse_args()

    builder = GraphBuilder(debug=args.debug)
    logger = SnapshotLogger(
        builder,
        output_file=args.log_file,
        interval=args.interval,
    )
    sniffer = RTPSSniffer(
        interface=args.interface,
        port_filter=args.port_filter or None,
        on_update_callback=builder.process_event,
        debug=args.debug,
    )
    shutdown_event = threading.Event()

    def request_shutdown(signum, frame):
        shutdown_event.set()

    signal.signal(signal.SIGINT, request_shutdown)
    signal.signal(signal.SIGTERM, request_shutdown)

    print(
        f"RIDS introspector: interface={args.interface}, "
        f"port_filter={args.port_filter or 'disabled'}, "
        f"interval={args.interval}s, gui={args.gui}"
    )

    try:
        logger.start()
        sniffer.start()

        if args.gui:
            GraphVisualizer(builder, interval_ms=int(args.interval * 1000)).start()
        elif not args.no_terminal:
            TerminalVisualizer(
                builder,
                interval=args.interval,
                table_width=args.table_width,
            ).run(shutdown_event)
        else:
            while not shutdown_event.wait(1.0):
                pass
    finally:
        sniffer.stop()
        logger.stop()

if __name__ == "__main__":
    main()