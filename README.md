# BinVis - Magnetic Binary Visualizer

**BinVis** is a modern, interactive Linux desktop application for reverse engineering and visualizing the control flow of ELF binaries. It uses a "magnetic" force-directed graph layout to organize function calls dynamically, providing an intuitive way to explore software architecture and logic.

## Features

*   **Interactive Control Flow Graph (CFG):**
    *   Nodes represent functions; edges represent calls.
    *   **Magnetic Physics:** Nodes naturally repel and attract based on connections.
    *   **Drag & Drop:** Rearrange nodes manually.
    *   **Zoom & Pan:** Navigate large graphs easily.
    *   **Directional Arrows:** Visual indication of caller/callee relationships.
*   **Binary Analysis:**
    *   **ELF Parsing:** Extracts function symbols and PLT entries.
    *   **Disassembly:** Integrates `Capstone` engine to show x86-64 assembly code.
    *   **Pseudo-Decompiler:** Heuristic-based translator converting assembly to simplified C-like logic.
    *   **Imports/PLT:** Lists external dependencies and their addresses.
*   **Modern UI:**
    *   Built with **PyQt6**.
    *   Dark theme with syntax highlighting.
    *   Tabbed interface for Info, Disassembly, Decompiler, and Imports.
    *   **Split View:** Adjustable 40/60 split between analysis tools and the visual graph.
    *   **Navigation:** Double-click function names in the decompiler to jump to their graph nodes.

## Installation

### Prerequisites
*   Python 3.8+
*   Linux (tested on Kali Linux)

### Setup
1.  Clone the repository (or download source).
2.  Create a virtual environment (recommended):
    ```bash
    python3 -m venv venv
    source venv/bin/activate
    ```
3.  Install dependencies:
    ```bash
    pip install PyQt6 pyelftools capstone networkx
    ```

## Usage

1.  **Launch the Application:**
    ```bash
    python BinVis/main.py
    ```
2.  **Open a Binary:**
    *   Click **File -> Open Binary** (or `Ctrl+O`).
    *   Select an unstripped ELF executable (e.g., `BinVis/spaghetti_bin`).
3.  **Explore:**
    *   **Left Click** a node to select it.
    *   **Right Click & Drag** to pan the view.
    *   **Scroll** to zoom.
    *   Use the **tabs** on the left to view details, assembly, or pseudo-code.

## Project Structure

*   `BinVis/main.py`: Entry point and main UI logic.
*   `BinVis/binary_analyzer.py`: Core backend for parsing ELF files and disassembling code.
*   `BinVis/graph_engine.py`: Physics engine for the force-directed graph layout.
*   `BinVis/ui/graph_widget.py`: Custom PyQt6 widget for rendering the graph.
*   `BinVis/ui/splash.py`: Startup splash screen.

## Testing
A test binary with "spaghetti code" logic is included for demonstration:
```bash
# Compile the test binary
gcc -g -no-pie -fno-inline BinVis/spaghetti.c -o BinVis/spaghetti_bin

# Run BinVis and load 'BinVis/spaghetti_bin'
```
