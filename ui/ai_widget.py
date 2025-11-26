import os
from PyQt6.QtWidgets import QWidget, QVBoxLayout, QTextEdit, QPushButton, QLabel, QLineEdit, QMessageBox, QHBoxLayout
from PyQt6.QtCore import QThread, pyqtSignal

# Try to import the library, handle failure gracefully
try:
    import google.generativeai as genai
    HAS_GENAI = True
except ImportError:
    HAS_GENAI = False

class AIWorker(QThread):
    finished = pyqtSignal(str, str) # result, type ('func' or 'full')
    error = pyqtSignal(str)

    def __init__(self, api_key, model_name, mode, data):
        super().__init__()
        self.api_key = api_key
        self.model_name = model_name
        self.mode = mode # 'func' or 'full'
        self.data = data # dict with necessary info

    def run(self):
        if not HAS_GENAI:
            self.error.emit("The 'google-generativeai' library is not installed.\nPlease run: pip install google-generativeai")
            return

        try:
            genai.configure(api_key=self.api_key)
            model = genai.GenerativeModel(self.model_name)
            
            if self.mode == 'func':
                prompt = (
                    f"You are a reverse engineering assistant.\n"
                    f"Analyze the following x86-64 assembly code for the function '{self.data['name']}'.\n"
                    f"1. Summarize what it does in plain English.\n"
                    f"2. Provide a C-like pseudocode representation.\n\n"
                    f"Code:\n{self.data['asm']}"
                )
            else: # Full Binary Resume
                prompt = (
                    f"You are a reverse engineering assistant.\n"
                    f"Provide a high-level global analysis of this binary based on the following summary stats:\n"
                    f"- Filename: {self.data['filename']}\n"
                    f"- Total Functions: {self.data['num_funcs']}\n"
                    f"- Total Calls: {self.data['num_edges']}\n"
                    f"- External Imports (PLT): {', '.join(self.data['imports'][:50])} ... (and more)\n"
                    f"- Entry Point Address: {hex(self.data['entry_point']) if self.data['entry_point'] else 'Unknown'}\n\n"
                    f"Please infer the likely purpose of this binary (e.g., is it a network tool, a calculator, malware, a game?) based on its imports and structure. "
                    f"Suggest which functions might be most interesting to investigate further."
                )
            
            response = model.generate_content(prompt)
            self.finished.emit(response.text, self.mode)
        except Exception as e:
            # Enhanced error handling to list models if 404
            error_str = str(e)
            if "404" in error_str and "not found" in error_str:
                try:
                    available_models = []
                    for m in genai.list_models():
                        if 'generateContent' in m.supported_generation_methods:
                            available_models.append(m.name)
                    
                    error_str += "\n\nAvailable models for your key:\n" + "\n".join(available_models)
                    error_str += "\n\nPlease copy one of these into the 'Model' field."
                except Exception as list_err:
                    error_str += f"\n\n(Could not list models: {list_err})"
            
            self.error.emit(error_str)

class AIWidget(QWidget):
    # Signals to send results back to MainWindow to display in the Right Panel
    analysis_complete = pyqtSignal(str, str) # result, type ('func' or 'full')

    def __init__(self):
        super().__init__()
        self.current_function = None
        self.current_asm = None
        self.binary_info = None # For full analysis
        self.init_ui()

    def init_ui(self):
        layout = QVBoxLayout(self)
        layout.setContentsMargins(10, 10, 10, 10)

        # Settings Row (API Key + Model)
        settings_layout = QHBoxLayout()
        
        # API Key Input
        self.api_key_input = QLineEdit()
        self.api_key_input.setPlaceholderText("API Key (sk-...")
        self.api_key_input.setEchoMode(QLineEdit.EchoMode.Password)
        self.api_key_input.setStyleSheet("""
            QLineEdit {
                background-color: #2d2d2d;
                color: #fff;
                border: 1px solid #3e3e3e;
                padding: 5px;
                border-radius: 4px;
            }
        """)
        # Check environment variable for default
        if "GEMINI_API_KEY" in os.environ:
            self.api_key_input.setText(os.environ["GEMINI_API_KEY"])
            
        settings_layout.addWidget(QLabel("API Key:"))
        settings_layout.addWidget(self.api_key_input, stretch=2)
        
        # Model Input
        self.model_input = QLineEdit()
        self.model_input.setPlaceholderText("Model Name")
        self.model_input.setText("gemini-2.0-flash") # Default
        self.model_input.setStyleSheet("""
            QLineEdit {
                background-color: #2d2d2d;
                color: #fff;
                border: 1px solid #3e3e3e;
                padding: 5px;
                border-radius: 4px;
            }
        """)
        settings_layout.addWidget(QLabel("Model:"))
        settings_layout.addWidget(self.model_input, stretch=1)

        layout.addLayout(settings_layout)

        # Analyze Full Binary Button
        self.analyze_full_btn = QPushButton("Analyze Full Binary (Resume)")
        self.analyze_full_btn.clicked.connect(self.run_full_analysis)
        self.analyze_full_btn.setEnabled(False)
        self.analyze_full_btn.setStyleSheet("""
            QPushButton {
                background-color: #2e7d32; /* Green */
                color: white;
                padding: 8px;
                border-radius: 4px;
                margin-top: 10px;
            }
            QPushButton:hover { background-color: #388e3c; }
            QPushButton:disabled { background-color: #444; color: #888; }
        """)
        layout.addWidget(self.analyze_full_btn)

        # Analyze Function Button
        self.analyze_func_btn = QPushButton("Analyze Current Function")
        self.analyze_func_btn.clicked.connect(self.run_func_analysis)
        self.analyze_func_btn.setStyleSheet("""
            QPushButton {
                background-color: #0d47a1; /* Blue */
                color: white;
                padding: 8px;
                border-radius: 4px;
                margin-top: 5px;
            }
            QPushButton:hover { background-color: #1565c0; }
            QPushButton:disabled { background-color: #444; color: #888; }
        """)
        layout.addWidget(self.analyze_func_btn)

        # Helper Label
        self.status_label = QLabel("AI Output will appear in the Right Panel.")
        self.status_label.setStyleSheet("color: #888; font-style: italic; margin-top: 10px;")
        self.status_label.setWordWrap(True)
        layout.addWidget(self.status_label)
        
        layout.addStretch()

    def set_binary_info(self, info_dict):
        self.binary_info = info_dict
        self.analyze_full_btn.setEnabled(True)

    def set_current_function(self, name, asm_code):
        self.current_function = name
        self.current_asm = asm_code
        self.analyze_func_btn.setEnabled(bool(asm_code))
        self.status_label.setText(f"Ready to analyze: {name}")

    def get_creds(self):
        api_key = self.api_key_input.text().strip()
        model_name = self.model_input.text().strip()
        if not api_key:
            QMessageBox.warning(self, "Missing Key", "Please enter a valid Google Gemini API Key.")
            return None, None
        if not model_name:
             QMessageBox.warning(self, "Missing Model", "Please enter a valid Model Name.")
             return None, None
        return api_key, model_name

    def run_full_analysis(self):
        key, model = self.get_creds()
        if not key: return
        
        if not self.binary_info:
            return

        self.analyze_full_btn.setEnabled(False)
        self.status_label.setText("Generating Global Resume... Please Wait.")
        
        self.worker = AIWorker(key, model, 'full', self.binary_info)
        self.worker.finished.connect(self.on_success)
        self.worker.error.connect(self.on_error)
        self.worker.start()

    def run_func_analysis(self):
        key, model = self.get_creds()
        if not key: return

        if not self.current_asm:
            return

        self.analyze_func_btn.setEnabled(False)
        self.status_label.setText(f"Analyzing {self.current_function}...")

        data = {'name': self.current_function, 'asm': self.current_asm}
        self.worker = AIWorker(key, model, 'func', data)
        self.worker.finished.connect(self.on_success)
        self.worker.error.connect(self.on_error)
        self.worker.start()

    def on_success(self, result, mode):
        self.analysis_complete.emit(result, mode)
        self.status_label.setText("Analysis Complete. Check the Right Panel.")
        self.analyze_full_btn.setEnabled(True)
        self.analyze_func_btn.setEnabled(True)

    def on_error(self, err_msg):
        QMessageBox.critical(self, "AI Error", err_msg)
        self.status_label.setText("Analysis Failed.")
        self.analyze_full_btn.setEnabled(True)
        self.analyze_func_btn.setEnabled(True)
