# Gemini Development Context

This file is intended for future AI agents (Gemini or others) to quickly understand the state of the **BinVis** project and resume development efficiently.

## Project Overview
**BinVis** is a Python-based GUI tool for visualizing the control flow of binaries (ELF & PE). It combines static analysis (parsing, disassembly) with a dynamic, force-directed graph visualization.
Recent updates have added a **GDB-based Debugger** and **Generative AI integration** for automated code analysis.

## Architecture
The project follows a modular structure separating the UI, analysis backend, rendering engine, and external integrations.

### 1. Core Components
*   **`BinVis/main.py`**:
    *   **Class:** `MainWindow`
    *   **Role:** Orchestrates the application. Manages a `QSplitter` layout with a Tabbed Left Panel (Info, ASM, Decomp, Imports, Debug, AI) and a Tabbed Right Panel (Graph, AI Results).
    *   **Features:** Handles file loading (ELF/PE), signals between widgets, and theming.

*   **`BinVis/binary_analyzer.py`**:
    *   **Class:** `BinaryAnalyzer`
    *   **Libraries:** `pyelftools` (ELF), `pefile` (PE), `capstone` (Disassembly), `networkx` (Graph).
    *   **Role:**
        1.  Detects format (ELF/PE).
        2.  Extracts symbols, imports, and entry points.
        3.  Disassembles `.text` (or equivalent) to find control flow.
        4.  Builds the Control Flow Graph (CFG).
        5.  **Decompilation:** `_simple_decompile` provides heuristic ASM-to-C translation.

*   **`BinVis/graph_engine.py`**:
    *   **Class:** `GraphEngine`
    *   **Role:** Implements custom physics simulation (Force-Directed Layout).
    *   **Physics:** Repulsion/Attraction model independent of rendering.

*   **`BinVis/debugger.py`**:
    *   **Class:** `DebuggerBackend`
    *   **Library:** `pygdbmi` (Machine Interface for GDB).
    *   **Role:** Manages the GDB subprocess. Handles Start/Stop, Stepping (Into/Over), and state retrieval (Registers, Stack, Disassembly context).

### 2. UI Components (`BinVis/ui/`)
*   **`graph_widget.py`**: High-performance graph rendering using `QPainter`.
*   **`debugger_widget.py`**: GUI for the debugger. Displays registers, stack, and highlighted disassembly.
*   **`ai_widget.py`**: Interface for Google's Gemini API (`google-generativeai`). Allows sending function ASM or binary summaries for AI analysis.

## Current Status (as of Nov 26, 2025)
*   **Working:**
    *   **Static Analysis:** Loading ELF x86-64 and basic PE binaries.
    *   **Visualization:** Interactive CFG with physics (Zoom/Pan/Drag).
    *   **Views:** Disassembly, Pseudo-Decompiler, Imports.
    *   **Debugger:** Fully functional GDB frontend (Stepping, Registers, Stack, Highlighting active line).
    *   **AI Integration:** Can query Gemini models to explain functions or summarize the binary.
    *   **Theming:** Dark/Light mode support.

*   **Limitations / Future Work:**
    *   **Arch Support:** Architecture support logic exists but rigorous testing on ARM/MIPS is needed.
    *   **Debugger:** Relies on system `gdb`. Needs to ensure `gdb` is in PATH or bundled. Currently assumes x86-like register names for display in some parts.
    *   **Large Binaries:** Physics engine O(N^2) loop needs optimization (Quadtree) for >500 nodes.
    *   **Stripped Binaries:** Heuristics for stripped binaries are basic.

## Conventions used
*   **UI Framework:** PyQt6.
*   **Graph Lib:** NetworkX (structure), Custom (layout).
*   **Debugger Lib:** pygdbmi.
*   **AI Lib:** google-generativeai.
*   **Code Style:** Standard Python PEP8.
*   **Pathing:** Absolute imports rooted at `BinVis/`.

## How to Resume
1.  **Check Dependencies:** `pip install -r BinVis/requirements.txt` (includes `pygdbmi`, `pefile`, `google-generativeai`).
2.  **System Req:** Ensure `gdb` is installed on the system for debugging features.
3.  **Run:** `python BinVis/main.py`
4.  **AI Setup:** Set `GEMINI_API_KEY` env var or enter it in the UI to use AI features.