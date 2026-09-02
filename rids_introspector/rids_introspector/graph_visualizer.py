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

import matplotlib.pyplot as plt
import matplotlib.animation as animation
import networkx as nx

class GraphVisualizer:
    def __init__(self, graph_builder, interval_ms: int = 1000):
        self.graph_builder = graph_builder
        self.interval_ms = interval_ms
        self.fig, self.ax = plt.subplots(figsize=(10, 7))
        self.ani = None  # Referencia persistente contra Garbage Collection
        self.pos = {}    # Caché de posiciones para mantener estabilidad visual

    def _update(self, frame):
        self.ax.clear()
        
        # Copia thread-safe del grafo
        G = self.graph_builder.get_graph_copy()

        if len(G.nodes) == 0:
            self.ax.set_title("Esperando tráfico RTPS...")
            return

        # Calcular o actualizar posiciones de forma estable
        self.pos = nx.spring_layout(G, pos=self.pos if self.pos else None)

        # Colores según el tipo de nodo
        colors = [
            "skyblue" if data.get("node_type") == "participant" else "lightgreen"
            for _, data in G.nodes(data=True)
        ]

        nx.draw_networkx(
            G, 
            self.pos, 
            ax=self.ax, 
            node_color=colors, 
            with_labels=True, 
            node_size=2000, 
            font_size=9
        )
        self.ax.set_title(f"Grafo ROS 2 / RTPS en tiempo real ({len(G.nodes)} nodos)")

    def start(self):
        # Asignar a self.ani evita la destrucción por Garbage Collector
        self.ani = animation.FuncAnimation(
            self.fig, 
            self._update, 
            interval=self.interval_ms, 
            cache_frame_data=False
        )
        plt.show()