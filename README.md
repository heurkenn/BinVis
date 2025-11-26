# BinVis - Magnetic Binary Visualizer

**BinVis** is a modern, interactive Linux desktop application for reverse engineering and visualizing the control flow of ELF binaries. It uses a "magnetic" force-directed graph layout to organize function calls dynamically, providing an intuitive way to explore software architecture and logic. Recent updates include a powerful GDB-based debugger and AI integration for advanced analysis.

## Features

*   **Interactive Control Flow Graph (CFG):**
    *   Nodes represent functions; edges represent calls.
    *   **Magnetic Physics:** Nodes naturally repel and attract based on connections.
    *   **Drag & Drop:** Rearrange nodes manually.
    *   **Zoom & Pan:** Navigate large graphs easily.
    *   **Directional Arrows:** Visual indication of caller/callee relationships.
*   **Binary Analysis:**
    *   **ELF/PE Parsing:** Extracts function symbols, PLT/GOT entries.
    *   **Disassembly:** Integrates `Capstone` engine to show x86-64 assembly code.
    *   **Pseudo-Decompiler:** Heuristic-based translator converting assembly to simplified C-like logic.
    *   **Imports/PLT:** Lists external dependencies and their addresses.
*   **Debugger Features:**
    *   Seamless **GDB Integration** for dynamic analysis.
    *   **Execution Control:** Step Into (si), Step Over (ni), Continue.
    *   **Real-time State View:** Displays Registers and Stack.
    *   **Optimized Performance:** Utilizes GDB/MI (Machine Interface) commands for faster communication.
    *   **Smart Updates:** Features disassembly caching, incremental register updates, and lazy stack updates to ensure high responsiveness even when rapidly stepping through code.
*   **AI Integration:**
    *   Leverages **Google Gemini API** for enhanced analysis.
    *   **Function Summaries:** Get AI-generated explanations of individual functions.
    *   **Binary Overviews:** Request high-level summaries and likely purpose of the loaded binary.
*   **Modern UI:**
    *   Built with **PyQt6**.
    *   Dark theme with syntax highlighting.
    *   Tabbed interface for Info, Disassembly, Decompiler, Imports, Debugger, and AI Controls.
    *   **Split View:** Adjustable layout between analysis tools and the visual graph.
    *   **Navigation:** Double-click function names in the decompiler to jump to their graph nodes.

## Installation

### Prerequisites
*   Python 3.8+
*   Linux (tested on Kali Linux)
*   `gdb` (GNU Debugger) must be installed and in your system's PATH for debugger features.
*   For AI features, you will need a Google Gemini API Key. You can set it as an environment variable `GEMINI_API_KEY` or enter it in the UI.

### Setup
1.  Clone the repository (or download source).
2.  Create a virtual environment (recommended):
    ```bash
    python3 -m venv venv
    source venv/bin/activate
    ```
3.  Install dependencies:
    ```bash
    pip install PyQt6 pyelftools capstone networkx pygdbmi google-generativeai pefile
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
    *   Use the **tabs** on the left to view details, assembly, pseudo-code, interact with the debugger, or use AI analysis.

## Project Structure

*   `BinVis/main.py`: Entry point and main UI logic.
*   `BinVis/binary_analyzer.py`: Core backend for parsing ELF/PE files and disassembling code.
*   `BinVis/graph_engine.py`: Physics engine for the force-directed graph layout.
*   `BinVis/debugger.py`: GDB interaction backend, handling execution control and data retrieval.
*   `BinVis/ui/graph_widget.py`: Custom PyQt6 widget for rendering the graph.
*   `BinVis/ui/debugger_widget.py`: PyQt6 GUI component for the debugger.
*   `BinVis/ui/ai_widget.py`: PyQt6 GUI component for Gemini AI integration.
*   `BinVis/ui/splash.py`: Startup splash screen.

## Testing
A test binary with "spaghetti code" logic is included for demonstration:
```bash
# Compile the test binary
gcc -g -no-pie -fno-inline BinVis/spaghetti.c -o BinVis/spaghetti_bin

# Run BinVis and load 'BinVis/spaghetti_bin'
```
