import sys
import os
from PyQt6.QtWidgets import QApplication, QMainWindow, QFileDialog, QMessageBox, QVBoxLayout, QWidget, QLabel, QSplitter, QTextEdit, QTabWidget
from PyQt6.QtGui import QAction, QIcon, QPalette, QColor, QTextCursor, QTextCharFormat
from PyQt6.QtCore import Qt, pyqtSignal

# Fix path to allow imports from BinVis package
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

try:
    from BinVis.binary_analyzer import BinaryAnalyzer
    from BinVis.graph_engine import GraphEngine
    from BinVis.ui.graph_widget import GraphWidget
    from BinVis.ui.splash import SplashScreen
    from BinVis.ui.ai_widget import AIWidget
    from BinVis.ui.debugger_widget import DebuggerWidget
    from BinVis.ui.preferences import PreferencesDialog
    from BinVis.ui.highlighter import AsmHighlighter, CHighlighter
    from BinVis.resources.translations import tr, TRANSLATIONS
    import BinVis.resources.translations as trans_module # to set global var
except ImportError:
    from binary_analyzer import BinaryAnalyzer
    from graph_engine import GraphEngine
    from ui.graph_widget import GraphWidget
    from ui.splash import SplashScreen
    from ui.ai_widget import AIWidget
    from ui.debugger_widget import DebuggerWidget
    from ui.preferences import PreferencesDialog
    from ui.highlighter import AsmHighlighter, CHighlighter
    from resources.translations import tr, TRANSLATIONS
    import resources.translations as trans_module

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
        
        # State
        self.current_theme = "Dark"
        
        # Setup Logic
        self.engine = GraphEngine()
        
        # Setup UI
        self.init_ui()
        self.setup_theme(self.current_theme)
        
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
        self.info_label = QLabel(tr("info_open"))
        self.info_label.setStyleSheet("padding: 5px; background-color: #252526; color: #ccc; border-bottom: 1px solid #3e3e3e;")
        self.left_layout.addWidget(self.info_label)
        
        # Left Tabs
        self.tab_widget = QTabWidget()
        self.tab_widget.setStyleSheet("""
            QTabWidget::pane { border: 0; }
            QTabBar::tab { background: #2d2d2d; color: #aaa; padding: 8px 15px; }
            QTabBar::tab:selected { background: #3e3e3e; color: #fff; }
        """)
        
        # Tab 1: Info
        self.details_panel = QTextEdit()
        self.details_panel.setReadOnly(True)
        self.details_panel.setText("Select a node to view details.")
        self.tab_widget.addTab(self.details_panel, tr("tab_info"))
        
        # Tab 2: Disassembly
        self.asm_panel = QTextEdit()
        self.asm_panel.setReadOnly(True)
        self.asm_panel.setLineWrapMode(QTextEdit.LineWrapMode.NoWrap) 
        self.asm_panel.setText("Select a node to view assembly.")
        
        # Attach Highlighter
        self.asm_highlighter = AsmHighlighter(self.asm_panel.document())
        
        self.tab_widget.addTab(self.asm_panel, tr("tab_asm"))

        # Tab 3: Decompiler (Pseudo-C)
        self.decomp_panel = ClickableTextEdit()
        self.decomp_panel.jump_requested.connect(self.on_decompiler_jump)
        self.decomp_panel.setReadOnly(True)
        self.decomp_panel.setLineWrapMode(QTextEdit.LineWrapMode.NoWrap)
        self.decomp_panel.setText("Select a node to view pseudo-C.")
        
        # Attach Highlighter
        self.c_highlighter = CHighlighter(self.decomp_panel.document())
        
        self.tab_widget.addTab(self.decomp_panel, tr("tab_decomp"))

        # Tab 4: Imports (PLT)
        self.imports_panel = QTextEdit()
        self.imports_panel.setReadOnly(True)
        self.imports_panel.setText("No binary loaded.")
        self.tab_widget.addTab(self.imports_panel, tr("tab_imports"))

        # Tab 5: Debugger (New!)
        self.debug_panel = DebuggerWidget()
        self.debug_panel.highlight_node.connect(self.on_node_clicked) # Kill feature: Highlight graph on stop
        self.tab_widget.addTab(self.debug_panel, tr("tab_debug"))

        # Tab 6: AI Controls
        self.ai_panel = AIWidget()
        self.ai_panel.analysis_complete.connect(self.on_ai_result)
        self.tab_widget.addTab(self.ai_panel, tr("tab_ai_ctrl")),
        
        self.left_layout.addWidget(self.tab_widget)
        self.splitter.addWidget(self.left_container)
        
        # --- Right Panel (Graph + AI Results) ---
        self.right_tab_widget = QTabWidget()
        self.right_tab_widget.setStyleSheet("""
             QTabWidget::pane { border: 0; }
             QTabBar::tab { background: #2d2d2d; color: #aaa; padding: 8px 15px; }
             QTabBar::tab:selected { background: #3e3e3e; color: #fff; }
        """)
        
        # Right Tab 1: Graph
        self.graph_widget = GraphWidget(self.engine)
        self.graph_widget.nodeClicked.connect(self.on_node_clicked)
        self.right_tab_widget.addTab(self.graph_widget, tr("tab_graph"))
        
        # Right Tab 2: Resume (Global Analysis)
        self.resume_panel = QTextEdit()
        self.resume_panel.setReadOnly(True)
        self.resume_panel.setPlaceholderText(tr("ai_placeholder"))
        self.right_tab_widget.addTab(self.resume_panel, tr("tab_resume"))
        
        # Right Tab 3: Functions (Func Analysis)
        self.func_ai_panel = QTextEdit()
        self.func_ai_panel.setReadOnly(True)
        self.func_ai_panel.setPlaceholderText(tr("ai_placeholder"))
        self.right_tab_widget.addTab(self.func_ai_panel, tr("tab_funcs")),
        
        self.splitter.addWidget(self.right_tab_widget)
        
        # Set Splitter Ratios (35% / 65%)
        self.splitter.setStretchFactor(0, 35)
        self.splitter.setStretchFactor(1, 65)
        
        # Menu
        self.create_menu()

    def create_menu(self):
        menu = self.menuBar()
        menu.clear() # Clear for re-creation (translation update) 
        
        file_menu = menu.addMenu(tr("menu_file"))
        
        open_action = QAction(tr("menu_open"), self)
        open_action.setShortcut("Ctrl+O")
        open_action.triggered.connect(self.open_file_dialog)
        file_menu.addAction(open_action)
        
        exit_action = QAction(tr("menu_exit"), self)
        exit_action.triggered.connect(self.close)
        file_menu.addAction(exit_action)
        
        edit_menu = menu.addMenu(tr("menu_edit"))
        pref_action = QAction(tr("menu_prefs"), self)
        pref_action.triggered.connect(self.open_preferences)
        edit_menu.addAction(pref_action)
        
        view_menu = menu.addMenu(tr("menu_view"))
        reset_action = QAction(tr("menu_reset"), self)
        reset_action.triggered.connect(self.reset_view)
        view_menu.addAction(reset_action)

    def open_preferences(self):
        dlg = PreferencesDialog(self, trans_module.CURRENT_LANG, self.current_theme)
        dlg.settings_applied.connect(self.apply_preferences)
        dlg.exec()

    def apply_preferences(self, lang, theme):
        # Apply Lang
        if lang != trans_module.CURRENT_LANG:
            trans_module.CURRENT_LANG = lang
            self.create_menu() # Refresh menu
            # Update Tab Titles
            self.tab_widget.setTabText(0, tr("tab_info"))
            self.tab_widget.setTabText(1, tr("tab_asm"))
            self.tab_widget.setTabText(2, tr("tab_decomp"))
            self.tab_widget.setTabText(3, tr("tab_imports"))
            self.tab_widget.setTabText(4, tr("tab_debug"))
            self.tab_widget.setTabText(5, tr("tab_ai_ctrl")),
            
            self.right_tab_widget.setTabText(0, tr("tab_graph"))
            self.right_tab_widget.setTabText(1, tr("tab_resume"))
            self.right_tab_widget.setTabText(2, tr("tab_funcs")),
            
            # Update Label
            if "No binary" in self.info_label.text() or "Open a" in self.info_label.text() or "Ouvrez" in self.info_label.text():
                 self.info_label.setText(tr("info_open"))

        # Apply Theme
        if theme != self.current_theme:
            self.setup_theme(theme)
            self.current_theme = theme

    def setup_theme(self, theme_name):
        app = QApplication.instance()
        app.setStyle("Fusion")
        
        palette = QPalette()
        if theme_name == "Dark":
            # Dark Theme Colors
            palette.setColor(QPalette.ColorRole.Window, QColor(53, 53, 53))
            palette.setColor(QPalette.ColorRole.WindowText, Qt.GlobalColor.white)
            palette.setColor(QPalette.ColorRole.Base, QColor(25, 25, 25))
            palette.setColor(QPalette.ColorRole.AlternateBase, QColor(53, 53, 53))
            palette.setColor(QPalette.ColorRole.ToolTipBase, Qt.GlobalColor.black)
            palette.setColor(QPalette.ColorRole.ToolTipText, Qt.GlobalColor.white)
            palette.setColor(QPalette.ColorRole.Text, Qt.GlobalColor.white)
            palette.setColor(QPalette.ColorRole.Button, QColor(53, 53, 53))
            palette.setColor(QPalette.ColorRole.ButtonText, Qt.GlobalColor.white)
            palette.setColor(QPalette.ColorRole.BrightText, Qt.GlobalColor.red)
            palette.setColor(QPalette.ColorRole.Link, QColor(42, 130, 218))
            palette.setColor(QPalette.ColorRole.Highlight, QColor(42, 130, 218))
            palette.setColor(QPalette.ColorRole.HighlightedText, Qt.GlobalColor.black)
            
            # Specific Panel Styles
            sheet = """
            QTextEdit { background-color: #1e1e1e; color: #d4d4d4; font-family: 'Consolas', 'Courier New', monospace; font-size: 13px; border: none; padding: 10px; }
            QTableWidget { background-color: #1e1e1e; color: #d4d4d4; gridline-color: #333; }
            """
        else:
            # Light Theme Colors
            palette.setColor(QPalette.ColorRole.Window, QColor(240, 240, 240))
            palette.setColor(QPalette.ColorRole.WindowText, Qt.GlobalColor.black)
            palette.setColor(QPalette.ColorRole.Base, Qt.GlobalColor.white)
            palette.setColor(QPalette.ColorRole.AlternateBase, QColor(233, 231, 227))
            palette.setColor(QPalette.ColorRole.ToolTipBase, Qt.GlobalColor.white)
            palette.setColor(QPalette.ColorRole.ToolTipText, Qt.GlobalColor.black)
            palette.setColor(QPalette.ColorRole.Text, Qt.GlobalColor.black)
            palette.setColor(QPalette.ColorRole.Button, QColor(240, 240, 240))
            palette.setColor(QPalette.ColorRole.ButtonText, Qt.GlobalColor.black)
            palette.setColor(QPalette.ColorRole.BrightText, Qt.GlobalColor.red)
            palette.setColor(QPalette.ColorRole.Highlight, QColor(76, 163, 224))
            palette.setColor(QPalette.ColorRole.HighlightedText, Qt.GlobalColor.white)

            # Specific Panel Styles
            sheet = """
            QTextEdit { background-color: #ffffff; color: #000000; font-family: 'Consolas', 'Courier New', monospace; font-size: 13px; border: none; padding: 10px; }
            QTableWidget { background-color: #ffffff; color: #000000; gridline-color: #ccc; }
            """
            
        app.setPalette(palette)
        
        # Apply specific styles to text panels
        self.details_panel.setStyleSheet(sheet)
        self.asm_panel.setStyleSheet(sheet)
        self.decomp_panel.setStyleSheet(sheet)
        self.imports_panel.setStyleSheet(sheet)
        self.resume_panel.setStyleSheet(sheet)
        self.func_ai_panel.setStyleSheet(sheet)
        # Debugger tables are styled in setup_theme or their own widgets, but we apply sheet here if needed
        
        # Info Label Style Update
        bg = "#252526" if theme_name == "Dark" else "#e0e0e0"
        fg = "#ccc" if theme_name == "Dark" else "#333"
        bd = "#3e3e3e" if theme_name == "Dark" else "#ccc"
        self.info_label.setStyleSheet(f"padding: 5px; background-color: {bg}; color: {fg}; border-bottom: 1px solid {bd};")


    def on_ai_result(self, result, mode):
        if mode == 'full':
            self.resume_panel.setMarkdown(result)
            self.right_tab_widget.setCurrentIndex(1) # Switch to Resume tab
        else:
            self.func_ai_panel.setMarkdown(result)
            self.right_tab_widget.setCurrentIndex(2) # Switch to Functions tab

    def on_decompiler_jump(self, target_name):
        """Navigate to the double-clicked function if it exists."""
        if target_name in self.engine.nodes:
            self.on_node_clicked(target_name)
            self.info_label.setText(f"Jumped to {target_name}")
        else:
            self.info_label.setText(f"Could not find node: {target_name}")

    def on_node_clicked(self, uid):
        """Updates the details panel with node info and focuses view."""
        # 1. Focus Camera
        self.graph_widget.center_on_node(uid)
        
        # 2. Update Info
        text = f"<h1>Function: {uid}</h1><br>"
        
        # Callers (Incoming)
        text += f"<h3>{tr('lbl_called_by')}</h3><ul>"
        callers = self.engine.incoming.get(uid, [])
        if callers:
            for caller in callers:
                text += f"<li>{caller}</li>"
        else:
            text += f"<li><i>{tr('lbl_entry')}</i></li>"
        text += "</ul><br>"
        
        # Callees (Outgoing)
        text += f"<h3>{tr('lbl_calls')}</h3><ul>"
        callees = self.engine.outgoing.get(uid, [])
        if callees:
            for callee in callees:
                text += f"<li>{callee}</li>"
        else:
            text += f"<li><i>{tr('lbl_leaf')}</i></li>"
        text += "</ul>"
        
        self.details_panel.setHtml(text)
        
        # 3. Update Disassembly & Decompiler
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

            # 4. Update AI Tab
            asm_code = node.data.get('asm', '')
            self.ai_panel.set_current_function(uid, asm_code)

    def open_file_dialog(self):
        fname, _ = QFileDialog.getOpenFileName(self, tr("menu_open"), "", "Executables (*);;All Files (*)")
        if fname:
            self.load_binary(fname)

    def load_binary(self, path):
        self.info_label.setText(tr("info_loading").format(os.path.basename(path)))
        QApplication.processEvents() # Force update
        
        try:
            analyzer = BinaryAnalyzer(path)
            graph = analyzer.analyze()
            
            node_count = graph.number_of_nodes()
            edge_count = graph.number_of_edges()
            
            self.engine.load_from_networkx(graph)
            self.info_label.setText(tr("info_loaded").format(os.path.basename(path), node_count, edge_count))
            
            # Populate Imports Tab
            imports_text = "Extracted Imports (PLT/DynSym):\n" + "="*30 + "\n"
            import_names = []
            for addr, name in analyzer.imports:
                imports_text += f"0x{addr:x}: {name}\n"
                import_names.append(name)
                
            self.imports_panel.setPlainText(imports_text)
            
            # Prepare Info for AI
            ai_info = {
                'filename': os.path.basename(path),
                'num_funcs': node_count,
                'num_edges': edge_count,
                'imports': import_names,
                'entry_point': getattr(analyzer, 'entry_point', None) # You might need to expose this in analyzer
            }
            self.ai_panel.set_binary_info(ai_info)
            
            # Pass binary to Debugger (if path is valid)
            self.debug_panel.set_binary(path)
            
            # Reset view to center
            self.reset_view()
            
        except Exception as e:
            QMessageBox.critical(self, tr("msg_error"), tr("msg_fail").format(str(e)))
            self.info_label.setText(tr("msg_error"))

    def reset_view(self):
        self.graph_widget.offset_x = 0
        self.graph_widget.offset_y = 0
        self.graph_widget.scale = 1.0

if __name__ == "__main__":
    app = QApplication(sys.argv)
    window = MainWindow()
    window.show()
    sys.exit(app.exec())