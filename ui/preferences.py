from PyQt6.QtWidgets import QDialog, QVBoxLayout, QHBoxLayout, QLabel, QComboBox, QPushButton
from PyQt6.QtCore import pyqtSignal
try:
    from BinVis.resources.translations import tr, CURRENT_LANG
except ImportError:
    from resources.translations import tr, CURRENT_LANG

class PreferencesDialog(QDialog):
    settings_applied = pyqtSignal(str, str) # lang, theme

    def __init__(self, parent=None, current_lang="en", current_theme="Dark"):
        super().__init__(parent)
        self.setWindowTitle(tr("pref_title"))
        self.resize(300, 150)
        
        self.layout = QVBoxLayout(self)
        
        # Language
        lang_layout = QHBoxLayout()
        lang_layout.addWidget(QLabel(tr("pref_lang")))
        self.lang_combo = QComboBox()
        self.lang_combo.addItems(["English", "Français"])
        self.lang_combo.setCurrentIndex(0 if current_lang == "en" else 1)
        lang_layout.addWidget(self.lang_combo)
        self.layout.addLayout(lang_layout)
        
        # Theme
        theme_layout = QHBoxLayout()
        theme_layout.addWidget(QLabel(tr("pref_theme")))
        self.theme_combo = QComboBox()
        self.theme_combo.addItems(["Dark", "Light"])
        self.theme_combo.setCurrentIndex(0 if current_theme == "Dark" else 1)
        theme_layout.addWidget(self.theme_combo)
        self.layout.addLayout(theme_layout)
        
        # Buttons
        btn_layout = QHBoxLayout()
        self.btn_save = QPushButton(tr("btn_save"))
        self.btn_save.clicked.connect(self.on_save)
        self.btn_cancel = QPushButton(tr("btn_cancel"))
        self.btn_cancel.clicked.connect(self.close)
        
        btn_layout.addStretch()
        btn_layout.addWidget(self.btn_cancel)
        btn_layout.addWidget(self.btn_save)
        self.layout.addLayout(btn_layout)
        
        # Style
        self.setStyleSheet("""
            QDialog { background-color: #2d2d2d; color: white; }
            QLabel { color: white; }
            QComboBox { background-color: #3e3e3e; color: white; padding: 5px; border: 1px solid #555; }
            QPushButton { background-color: #0d47a1; color: white; padding: 5px 15px; border: none; }
            QPushButton:hover { background-color: #1565c0; }
        """)

    def on_save(self):
        lang_code = "en" if self.lang_combo.currentIndex() == 0 else "fr"
        theme_name = self.theme_combo.currentText()
        self.settings_applied.emit(lang_code, theme_name)
        self.accept()
