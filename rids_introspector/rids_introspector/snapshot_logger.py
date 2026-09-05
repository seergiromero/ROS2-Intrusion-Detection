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

import json
import threading
import time
from pathlib import Path
from typing import Optional

class SnapshotLogger:
    def __init__(self, graph_builder, output_file: str = "snapshots.jsonl", interval: float = 1.0):
        if interval <= 0:
            raise ValueError("Snapshot interval must be greater than zero")

        self.graph_builder = graph_builder
        self.output_file = output_file
        self.interval = interval
        self._running = False
        self._thread: Optional[threading.Thread] = None
        self._snapshot_count = 0

    def start(self):
        if self._running:
            return

        self._running = True
        self._thread = threading.Thread(target=self._run, daemon=True)
        self._thread.start()

    def stop(self):
        self._running = False
        if self._thread:
            self._thread.join()

    def _run(self):
        output_path = Path(self.output_file)
        output_path.parent.mkdir(parents=True, exist_ok=True)

        self._snapshot_count = self._starting_snapshot_id()

        with output_path.open("a", encoding="utf-8") as f:
            while self._running:
                snapshot = self.graph_builder.get_snapshot_dict()
                record = {
                    "snapshot_id": self._snapshot_count,
                    "timestamp": time.time(),
                    "datetime": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                    "graph": snapshot
                }
                f.write(json.dumps(record) + "\n")
                f.flush()
                
                self._snapshot_count += 1
                time.sleep(self.interval)

    def _starting_snapshot_id(self) -> int:
        """Return the next snapshot_id, one past the highest id in the file."""
        output_path = Path(self.output_file)
        if not output_path.is_file():
            return 0
        highest = -1
        try:
            with output_path.open("r", encoding="utf-8") as stream:
                for line in stream:
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        record = json.loads(line)
                    except json.JSONDecodeError:
                        continue
                    value = record.get("snapshot_id")
                    if isinstance(value, int) and value > highest:
                        highest = value
        except OSError:
            pass
        return highest + 1
