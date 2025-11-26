from PyQt6.QtWidgets import QWidget, QLabel, QVBoxLayout
from PyQt6.QtCore import Qt, QTimer, QPropertyAnimation, QEasingCurve
from PyQt6.QtGui import QFont

class SplashScreen(QWidget):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setAttribute(Qt.WidgetAttribute.WA_TransparentForMouseEvents) # Click through
        self.setStyleSheet("background-color: rgba(18, 18, 18, 240); color: #00bcd4;")
        
        layout = QVBoxLayout(self)
        layout.setAlignment(Qt.AlignmentFlag.AlignCenter)
        
        # Unicode Logo
        logo_text = """
    ╔══╗╔╗
    ║╔╗╠╝║
    ║╔╗╠╗║
    ╚══╝╚╝
BINVIS v1.0
        """
        self.label = QLabel(logo_text)
        self.label.setFont(QFont("Courier New", 24, QFont.Weight.Bold))
        self.label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        layout.addWidget(self.label)
        
        # Fade out logic
        self.timer = QTimer(self)
        self.timer.singleShot(1500, self.start_fade)

    def start_fade(self):
        self.anim = QPropertyAnimation(self, b"windowOpacity")
        self.anim.setDuration(1000) # 1 second fade
        self.anim.setStartValue(1.0)
        self.anim.setEndValue(0.0)
        self.anim.setEasingCurve(QEasingCurve.Type.OutQuad)
        self.anim.finished.connect(self.hide)
        self.anim.start()
