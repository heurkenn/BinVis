import sys
import os
from PyQt6.QtWidgets import QApplication, QMainWindow, QFileDialog, QMessageBox, QVBoxLayout, QWidget, QLabel, QSplitter, QTextEdit, QTabWidget
from PyQt6.QtGui import QAction, QIcon
from PyQt6.QtCore import Qt, pyqtSignal

# Fix path to allow imports from BinVis package
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

try:
    from BinVis.binary_analyzer import BinaryAnalyzer
    from BinVis.graph_engine import GraphEngine
    from BinVis.ui.graph_widget import GraphWidget
    from BinVis.ui.splash import SplashScreen
except ImportError:
    from binary_analyzer import BinaryAnalyzer
    from graph_engine import GraphEngine
    from ui.graph_widget import GraphWidget
    from ui.splash import SplashScreen

class ClickableTextEdit(QTextEdit):
    jump_requested = pyqtSignal(str)

    def mouseDoubleClickEvent(self, event):
        # Get word under cursor
        cursor = self.cursorForPosition(event.position().toPoint())
        cursor.select(cursor.SelectionType.WordUnderCursor)
        text = cursor.selectedText()
        if text:
            # Clean up (remove parens if any)
            text = text.replace("(", "").replace(")", "").replace(";", "")
            self.jump_requested.emit(text)
        super().mouseDoubleClickEvent(event)

class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("BinVis - Magnetic Binary Visualizer")
        self.resize(1200, 800)
        
        # Setup Logic
        self.engine = GraphEngine()
        
        # Setup UI
        self.init_ui()
        self.setup_dark_theme()
        
        # Show Splash
        self.show_splash()
        
        # Start Fullscreen
        self.showFullScreen()

    def show_splash(self):
        self.splash = SplashScreen(self.central_widget)
        self.splash.resize(self.size())
        self.splash.show()
        
    def resizeEvent(self, event):
        if hasattr(self, 'splash'):
            self.splash.resize(self.size())
        super().resizeEvent(event)

    def init_ui(self):
        # Central Widget
        self.central_widget = QWidget()
        self.setCentralWidget(self.central_widget)
        
        # Main Layout
        self.main_layout = QVBoxLayout(self.central_widget)
        self.main_layout.setContentsMargins(0, 0, 0, 0)
        
        # Splitter
        self.splitter = QSplitter(Qt.Orientation.Horizontal)
        self.main_layout.addWidget(self.splitter)
        
        # --- Left Panel Container ---
        self.left_container = QWidget()
        self.left_layout = QVBoxLayout(self.left_container)
        self.left_layout.setContentsMargins(0, 0, 0, 0)
        self.left_layout.setSpacing(0)
        
        # Info Bar (Now inside left panel)
        self.info_label = QLabel("Open a binary file to visualize its control flow.")
        self.info_label.setStyleSheet("padding: 5px; background-color: #252526; color: #ccc; border-bottom: 1px solid #3e3e3e;")
        self.left_layout.addWidget(self.info_label)
        
        # Tabs
        self.tab_widget = QTabWidget()
        self.tab_widget.setStyleSheet("""
            QTabWidget::pane { border: 0; }
            QTabBar::tab { background: #2d2d2d; color: #aaa; padding: 8px 15px; }
            QTabBar::tab:selected { background: #3e3e3e; color: #fff; }
        """)
        
        # Tab 1: Info
        self.details_panel = QTextEdit()
        self.details_panel.setReadOnly(True)
        self.details_panel.setStyleSheet("""
            QTextEdit {
                background-color: #1e1e1e;
                color: #d4d4d4;
                font-family: 'Consolas', 'Courier New', monospace;
                font-size: 14px;
                border: none;
                padding: 10px;
            }
        """)
        self.details_panel.setText("Select a node to view details.")
        self.tab_widget.addTab(self.details_panel, "Info")
        
        # Tab 2: Disassembly
        self.asm_panel = QTextEdit()
        self.asm_panel.setReadOnly(True)
        self.asm_panel.setLineWrapMode(QTextEdit.LineWrapMode.NoWrap) # Better for code
        self.asm_panel.setStyleSheet("""
            QTextEdit {
                background-color: #1e1e1e;
                color: #a6e22e; /* Monokai Green */
                font-family: 'Consolas', 'Courier New', monospace;
                font-size: 13px;
                border: none;
                padding: 10px;
            }
        """)
        self.asm_panel.setText("Select a node to view assembly.")
        self.tab_widget.addTab(self.asm_panel, "Disassembly")

        # Tab 3: Decompiler (Pseudo-C)
        self.decomp_panel = ClickableTextEdit()
        self.decomp_panel.jump_requested.connect(self.on_decompiler_jump)
        self.decomp_panel.setReadOnly(True)
        self.decomp_panel.setLineWrapMode(QTextEdit.LineWrapMode.NoWrap)
        self.decomp_panel.setStyleSheet("""
            QTextEdit {
                background-color: #1e1e1e;
                color: #66d9ef; /* Monokai Blue */
                font-family: 'Consolas', 'Courier New', monospace;
                font-size: 13px;
                border: none;
                padding: 10px;
            }
        """)
        self.decomp_panel.setText("Select a node to view pseudo-C.")
        self.tab_widget.addTab(self.decomp_panel, "Decompiler")

        # Tab 4: Imports (PLT)
        self.imports_panel = QTextEdit()
        self.imports_panel.setReadOnly(True)
        self.imports_panel.setStyleSheet("""
            QTextEdit {
                background-color: #1e1e1e;
                color: #fd971f; /* Monokai Orange */
                font-family: 'Consolas', 'Courier New', monospace;
                font-size: 13px;
                border: none;
                padding: 10px;
            }
        """)
        self.imports_panel.setText("No binary loaded.")
        self.tab_widget.addTab(self.imports_panel, "Imports")
        
        self.left_layout.addWidget(self.tab_widget)
        
        # Add Left Container to Splitter
        self.splitter.addWidget(self.left_container)
        
        # --- Right Panel (Graph) ---
        self.graph_widget = GraphWidget(self.engine)
        self.graph_widget.nodeClicked.connect(self.on_node_clicked)
        self.splitter.addWidget(self.graph_widget)
        
        # Set Splitter Ratios (40% / 60%)
        self.splitter.setStretchFactor(0, 2)
        self.splitter.setStretchFactor(1, 3)
        
        # Menu
        menu = self.menuBar()
        file_menu = menu.addMenu("File")
        
        open_action = QAction("Open Binary...", self)
        open_action.setShortcut("Ctrl+O")
        open_action.triggered.connect(self.open_file_dialog)
        file_menu.addAction(open_action)
        
        exit_action = QAction("Exit", self)
        exit_action.triggered.connect(self.close)
        file_menu.addAction(exit_action)
        
        view_menu = menu.addMenu("View")
        reset_action = QAction("Reset View", self)
        reset_action.triggered.connect(self.reset_view)
        view_menu.addAction(reset_action)

    def on_decompiler_jump(self, target_name):
        """Navigate to the double-clicked function if it exists."""
        if target_name in self.engine.nodes:
            self.on_node_clicked(target_name)
            # Optional: Move camera to node? (Requires engine -> GraphWidget communication)
            self.info_label.setText(f"Jumped to {target_name}")
        else:
            self.info_label.setText(f"Could not find node: {target_name}")

    def on_node_clicked(self, uid):
        """Updates the details panel with node info."""
        # 1. Update Info
        text = f"<h1>Function: {uid}</h1><br>"
        
        # Callers (Incoming)
        text += "<h3>Called By:</h3><ul>"
        callers = self.engine.incoming.get(uid, [])
        if callers:
            for caller in callers:
                text += f"<li>{caller}</li>"
        else:
            text += "<li><i>(Entry Point or Unused)</i></li>"
        text += "</ul><br>"
        
        # Callees (Outgoing)
        text += "<h3>Calls:</h3><ul>"
        callees = self.engine.outgoing.get(uid, [])
        if callees:
            for callee in callees:
                text += f"<li>{callee}</li>"
        else:
            text += "<li><i>(Leaf Function)</i></li>"
        text += "</ul>"
        
        self.details_panel.setHtml(text)
        
        # 2. Update Disassembly & Decompiler
        node = self.engine.nodes.get(uid)
        if node:
            # ASM
            if 'asm' in node.data:
                self.asm_panel.setPlainText(node.data['asm'])
            else:
                self.asm_panel.setPlainText("; No assembly available for this node.")
                
            # Decompiler
            if 'decomp' in node.data:
                 # Get address if available
                 addr_str = ""
                 if 'address' in node.data:
                     addr_str = f" @ 0x{node.data['address']:x}"
                 
                 header = f"void {uid}(){addr_str} {{\n"
                 self.decomp_panel.setPlainText(header + node.data['decomp'] + "\n}")
            else:
                 self.decomp_panel.setPlainText("// No decompilation available.")

    def setup_dark_theme(self):
        # Basic Fusion Dark Palette
        app = QApplication.instance()
        app.setStyle("Fusion")
        
        # We can add a QPalette here if we want to style the menus/dialogs
        # For now, the graph widget handles its own dark mode

    def open_file_dialog(self):
        fname, _ = QFileDialog.getOpenFileName(self, "Open Binary", "", "Executables (*);;All Files (*)")
        if fname:
            self.load_binary(fname)

    def load_binary(self, path):
        self.info_label.setText(f"Analyzing {os.path.basename(path)}...")
        QApplication.processEvents() # Force update
        
        try:
            analyzer = BinaryAnalyzer(path)
            graph = analyzer.analyze()
            
            node_count = graph.number_of_nodes()
            edge_count = graph.number_of_edges()
            
            self.engine.load_from_networkx(graph)
            self.info_label.setText(f"Loaded {os.path.basename(path)}: {node_count} functions, {edge_count} calls.")
            
            # Populate Imports Tab
            imports_text = "Extracted Imports (PLT/DynSym):\n" + "="*30 + "\n"
            # analyzer.imports is now a list of tuples (addr, name)
            for addr, name in analyzer.imports:
                imports_text += f"0x{addr:x}: {name}\n"
                
            self.imports_panel.setPlainText(imports_text)
            
            # Reset view to center
            self.reset_view()
            
        except Exception as e:
            QMessageBox.critical(self, "Analysis Error", f"Failed to analyze binary:\n{str(e)}")
            self.info_label.setText("Analysis failed.")

    def reset_view(self):
        self.graph_widget.offset_x = 0
        self.graph_widget.offset_y = 0
        self.graph_widget.scale = 1.0

if __name__ == "__main__":
    app = QApplication(sys.argv)
    window = MainWindow()
    window.show()
    sys.exit(app.exec())
