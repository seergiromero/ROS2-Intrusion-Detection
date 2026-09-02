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
import sys
from rids_introspector.rtps_sniffer import RTPSSniffer
from rids_introspector.graph_builder import GraphBuilder
from rids_introspector.snapshot_logger import SnapshotLogger
from rids_introspector.graph_visualizer import GraphVisualizer

def main():
    parser = argparse.ArgumentParser(description="RIDS Network Introspector")
    parser.add_argument("--interface", default="lo", help="Network interface (default: lo)")
    parser.add_argument("--debug", default="False")
    parser.add_argument("--gui", action="store_true", help="Enable live Matplotlib graph")
    parser.add_argument("--log-file", default="snapshots.jsonl", help="Output path for snapshots")
    args, _ = parser.parse_known_args()

    # 1. Instanciar componentes
    builder = GraphBuilder()
    
    # Nota: usa args.log_file con guion bajo
    logger = SnapshotLogger(builder, output_file=args.log_file)
    
    # Corregido: parámetro 'on_update_callback'
    sniffer = RTPSSniffer(
        interface=args.interface, 
        on_update_callback=builder.process_event
    )

    # 2. Iniciar tareas en segundo plano
    logger.start()
    sniffer.start()  # AsyncSniffer ya se lanza asíncronamente

    # 3. Hilo principal: GUI o Bucle de espera
    visualizer = GraphVisualizer(builder)
    visualizer.start()  # Bloqueante (Matplotlib GUI)

if __name__ == "__main__":
    main()