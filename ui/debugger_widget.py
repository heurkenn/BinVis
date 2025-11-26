from PyQt6.QtWidgets import QWidget, QVBoxLayout, QHBoxLayout, QPushButton, QTextEdit, QLabel, QTableWidget, QTableWidgetItem, QHeaderView, QInputDialog, QComboBox
from PyQt6.QtGui import QColor
from PyQt6.QtCore import pyqtSignal, Qt, QThread
import re
try:
    from BinVis.debugger import DebuggerBackend
except ImportError:
    from debugger import DebuggerBackend

class DebuggerWidget(QWidget):
    highlight_node = pyqtSignal(str) # func_name
    
    # Signals to worker thread
    cmd_start = pyqtSignal(str, list, str) # path, args, flavor
    cmd_stop = pyqtSignal()
    cmd_step_into = pyqtSignal()
    cmd_step_over = pyqtSignal()
    cmd_continue = pyqtSignal()
    cmd_set_flavor = pyqtSignal(str)

    def __init__(self):
        super().__init__()
        
        # Threading Setup
        self.thread = QThread()
        self.backend = DebuggerBackend()
        self.backend.moveToThread(self.thread)
        
        # Connect Signals (UI -> Backend)
        self.cmd_start.connect(self.backend.start_session)
        self.cmd_stop.connect(self.backend.stop_session)
        self.cmd_step_into.connect(self.backend.step_into)
        self.cmd_step_over.connect(self.backend.step_over)
        self.cmd_continue.connect(self.backend.continue_exec)
        self.cmd_set_flavor.connect(self.backend.set_flavor)
        
        # Connect Signals (Backend -> UI)
        self.backend.console_output.connect(self.log_console) # We keep a mini console or log to status
        self.backend.stopped_at.connect(self.on_stop)
        self.backend.registers_updated.connect(self.update_regs)
        self.backend.stack_updated.connect(self.update_stack)
        self.backend.disassembly_updated.connect(self.on_disassembly_updated)
        self.backend.error_occurred.connect(self.log_error)
        
        self.thread.start()
        
        self.current_binary = None
        self.init_ui()

    def cleanup(self):
        self.thread.quit()
        self.thread.wait()

    def init_ui(self):
        layout = QVBoxLayout(self)
        layout.setContentsMargins(5, 5, 5, 5)

        # Controls Row 1
        row1_layout = QHBoxLayout()
        self.btn_start = QPushButton("Start Debug")
        self.btn_start.setStyleSheet("background-color: #2e7d32; color: white;")
        self.btn_start.clicked.connect(self.start_debug)
        
        self.btn_stop = QPushButton("Stop")
        self.btn_stop.setStyleSheet("background-color: #c62828; color: white;")
        self.btn_stop.clicked.connect(lambda: self.cmd_stop.emit())
        
        self.syntax_combo = QComboBox()
        self.syntax_combo.addItems(["Intel", "AT&T"])
        self.syntax_combo.currentIndexChanged.connect(self.on_syntax_changed)

        row1_layout.addWidget(self.btn_start)
        row1_layout.addWidget(self.btn_stop)
        row1_layout.addWidget(QLabel("Syntax:"))
        row1_layout.addWidget(self.syntax_combo)
        layout.addLayout(row1_layout)
        
        # Controls Row 2
        row2_layout = QHBoxLayout()
        self.btn_step = QPushButton("Step Into (si)")
        self.btn_step.clicked.connect(lambda: self.cmd_step_into.emit())
        
        self.btn_next = QPushButton("Step Over (ni)")
        self.btn_next.clicked.connect(lambda: self.cmd_step_over.emit())
        
        self.btn_cont = QPushButton("Continue (c)")
        self.btn_cont.clicked.connect(lambda: self.cmd_continue.emit())
        
        row2_layout.addWidget(self.btn_step)
        row2_layout.addWidget(self.btn_next)
        row2_layout.addWidget(self.btn_cont)
        layout.addLayout(row2_layout)

        # Status Bar (Mini Console)
        self.lbl_status = QLabel("Status: Idle")
        self.lbl_status.setStyleSheet("color: #aaa; font-weight: bold; padding: 5px; border: 1px solid #333;")
        layout.addWidget(self.lbl_status)

        # Split: Registers (Left) | Instructions (Center) | Stack (Right)
        split_layout = QHBoxLayout()
        
        # Regs (25%)
        self.reg_table = QTableWidget()
        self.reg_table.setColumnCount(2)
        self.reg_table.setHorizontalHeaderLabels(["Reg", "Value"])
        self.reg_table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Stretch)
        self.reg_table.verticalHeader().setVisible(False)
        self.reg_table.setStyleSheet("background-color: #1e1e1e; color: #d4d4d4; gridline-color: #333;")
        split_layout.addWidget(self.reg_table, stretch=25)
        
        # Instruction View (50%)
        self.inst_view = QTextEdit()
        self.inst_view.setReadOnly(True)
        self.inst_view.setStyleSheet("""
            QTextEdit {
                background-color: #121212;
                color: #d4d4d4;
                font-family: 'Consolas', 'Courier New', monospace;
                font-size: 12px;
                border: 1px solid #333;
            }
        """)
        split_layout.addWidget(self.inst_view, stretch=50)

        # Stack View (25%) - Replaced Console
        self.stack_table = QTableWidget()
        self.stack_table.setColumnCount(2)
        self.stack_table.setHorizontalHeaderLabels(["Address", "Value"])
        self.stack_table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Stretch)
        self.stack_table.verticalHeader().setVisible(False)
        self.stack_table.setStyleSheet("background-color: #1e1e1e; color: #d4d4d4; gridline-color: #333;")
        split_layout.addWidget(self.stack_table, stretch=25)
        
        layout.addLayout(split_layout)

    def set_binary(self, path):
        self.current_binary = path
        self.lbl_status.setText(f"Ready: {path}")

    def start_debug(self):
        if not self.current_binary:
            self.log_error("No binary loaded!")
            return
        
        text, ok = QInputDialog.getText(self, "Debug Arguments", "Arguments (optional):")
        args = text.split() if ok and text else []
        
        flavor = self.syntax_combo.currentText().lower()
        if "at&t" in flavor: flavor = "att"
        
        # Emit signal to start in thread
        self.cmd_start.emit(self.current_binary, args, flavor)
        self.lbl_status.setText("Starting...")

    def on_syntax_changed(self, index):
        flavor = self.syntax_combo.itemText(index).lower()
        if "at&t" in flavor: flavor = "att"
        self.cmd_set_flavor.emit(flavor)

    # Slots for Backend Updates
    def log_console(self, text):
        # We don't have a big console anymore, maybe just update status or print to stdout for dev
        # Or we can append to status if it's short
        if len(text) < 100:
            self.lbl_status.setText(f"GDB: {text}")
        print(f"GDB: {text}")

    def log_error(self, text):
        self.lbl_status.setText(f"Error: {text}")

    def on_stop(self, info):
        func = info['func']
        addr = info['addr']
        self.lbl_status.setText(f"Stopped: {func} @ {addr}")
        
        # UI Updates
        if func and func != '??':
            self.highlight_node.emit(func)

    def on_disassembly_updated(self, lines, active_idx):
        html = ""
        if lines:
            for i, line in enumerate(lines):
                clean_line = line.replace("=>", "  ")
                anchor = f"id='current'" if i == active_idx else ""
                
                # Highlights
                if "cmp" in clean_line.lower():
                    clean_line = re.sub(r'\b(eax|ebx|ecx|edx|esi|edi|ebp|esp|rax|rbx|rcx|rdx|rsi|rdi|rbp|rsp|r8|r9|r10|r11|r12|r13|r14|r15)\b', 
                                        r"<span style='color: #ff5555;'>\1</span>", clean_line, flags=re.IGNORECASE)
                if re.search(r'\b(jmp|je|jz|jne|jnz|jg|jge|jl|jle|ja|jb|call)\b', clean_line, re.IGNORECASE):
                    clean_line = re.sub(r'(0x[0-9a-f]+)', r"<span style='color: #f1fa8c;'>\1</span>", clean_line, flags=re.IGNORECASE)
                    clean_line = re.sub(r'(<[^>]+>)', r"<span style='color: #f1fa8c;'>\1</span>", clean_line)

                if i < active_idx:
                    html += f"<div style='color: #888;'>{clean_line}</div>"
                elif i == active_idx:
                    html += f"<div {anchor} style='color: #4caf50; background-color: #1e3320;'>{clean_line}</div>"
                else:
                    html += f"<div style='color: #fff;'>{clean_line}</div>"
        else:
            html = "<div style='color: #888;'>No disassembly available.</div>"
            
        self.inst_view.setHtml(html)
        if active_idx != -1:
            self.inst_view.scrollToAnchor("current")

    def update_regs(self, regs):
        self.reg_table.setRowCount(len(regs))
        for i, (name, val) in enumerate(regs.items()):
            self.reg_table.setItem(i, 0, QTableWidgetItem(name))
            self.reg_table.setItem(i, 1, QTableWidgetItem(val))

    def update_stack(self, stack_data):
        self.stack_table.setRowCount(len(stack_data))
        for i, (addr, val) in enumerate(stack_data):
            item_addr = QTableWidgetItem(addr)
            item_val = QTableWidgetItem(val)
            if addr:
                item_addr.setBackground(QColor("#2d2d2d"))
            
            self.stack_table.setItem(i, 0, item_addr)
            self.stack_table.setItem(i, 1, item_val)
