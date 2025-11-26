# Gemini Development Context

This file is intended for future AI agents (Gemini or others) to quickly understand the state of the **BinVis** project and resume development efficiently.

## Project Overview
**BinVis** is a Python-based GUI tool for visualizing the control flow of Linux ELF executables. It combines static analysis (ELF parsing, disassembly) with a dynamic, force-directed graph visualization.

## Architecture
The project follows a modular structure separating the UI, analysis backend, and rendering engine.

### 1. Core Components
*   **`binvis/main.py`**:
    *   **Class:** `MainWindow`
    *   **Role:** Orchestrates the application. Manages the `QSplitter` layout (Left: Tabs, Right: Graph), handles file loading, and connects UI signals (like node clicks) to updates in the tabs.
    *   **Key Feature:** `ClickableTextEdit` class implements double-click navigation in the Decompiler tab.

*   **`binvis/binary_analyzer.py`**:
    *   **Class:** `BinaryAnalyzer`
    *   **Libraries:** `pyelftools` (ELF parsing), `capstone` (Disassembly), `networkx` (Graph structure).
    *   **Role:**
        1.  Extracts function symbols from `.symtab`.
        2.  Extracts PLT/GOT imports from `.rela.plt` / `.dynsym`.
        3.  Disassembles `.text` section to find `call` instructions.
        4.  Builds a `networkx.DiGraph` where nodes are functions and edges are calls.
        5.  **Decompilation:** `_simple_decompile` provides a heuristic, regex-like translation of ASM to Pseudo-C.

*   **`binvis/graph_engine.py`**:
    *   **Class:** `GraphEngine` & `Node`
    *   **Role:** Implements a custom physics simulation (Force-Directed Layout) independent of the rendering library.
    *   **Physics:** Nodes have repulsion; connected edges have spring attraction; global center gravity.
    *   **Data:** Maintains `incoming` and `outgoing` adjacency lists for O(1) lookup.

*   **`binvis/ui/graph_widget.py`**:
    *   **Class:** `GraphWidget` (inherits `QWidget`)
    *   **Role:** High-performance custom rendering using `QPainter`.
    *   **Features:** 60FPS timer for physics, coordinate transformation (World <-> Screen), zoom/pan logic, arrow drawing.

## Current Status (as of Nov 26, 2025)
*   **Working:**
    *   Loading ELF x86-64 binaries.
    *   Visualizing call graphs with physics.
    *   Full interaction (Zoom, Pan, Drag).
    *   Disassembly view (Capstone integration).
    *   Imports view (PLT extraction).
    *   Pseudo-Decompiler with navigation (Double-click function names to jump).
    *   Dark UI theme.

*   **Limitations / Future Work:**
    *   **Arch Support:** Currently hardcoded for `x86-64`. Needs expansion for ARM/MIPS in `BinaryAnalyzer`.
    *   **Decompiler:** The `_simple_decompile` is very basic (text substitution). Integration with a real decompiler (like Ghidra headless or R2) would be a major upgrade.
    *   **Large Binaries:** The O(N^2) physics loop in `GraphEngine` might slow down with >500 nodes. Optimization (Quadtree or Barnes-Hut) needed for large binaries.
    *   **Stripped Binaries:** Relies heavily on `.symtab`. Needs heuristics/signature matching for stripped binaries.

## Conventions used
*   **UI Framework:** PyQt6.
*   **Graph Lib:** NetworkX (for structure), Custom (for layout/physics).
*   **Code Style:** Standard Python PEP8.
*   **Pathing:** Absolute imports rooted at `binvis/`.

## How to Resume
1.  **Check Dependencies:** Ensure `PyQt6`, `pyelftools`, `capstone`, `networkx` are installed.
2.  **Run:** Execute `binvis/main.py` to verify the current state.
3.  **Debug:** Use the `binvis/spaghetti.c` -> `binvis/spaghetti_bin` for quick iteration on graph logic.
