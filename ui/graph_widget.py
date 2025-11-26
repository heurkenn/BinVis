from PyQt6.QtWidgets import QWidget
from PyQt6.QtCore import QTimer, Qt, QPointF, QRectF, pyqtSignal
from PyQt6.QtGui import QPainter, QColor, QPen, QBrush, QFont, QPainterPath, QTransform

import math

class GraphWidget(QWidget):
    nodeClicked = pyqtSignal(str)

    def __init__(self, engine, parent=None):
        super().__init__(parent)
        self.engine = engine
        
        # Rendering settings
        self.node_radius = 20
        self.node_color = QColor("#00bcd4") # Cyan
        self.node_text_color = QColor("#ffffff")
        self.edge_color = QColor("#555555")
        self.bg_color = QColor("#121212")
        
        # Camera
        self.offset_x = 0
        self.offset_y = 0
        self.scale = 1.0
        self.min_scale = 0.1
        self.max_scale = 5.0
        
        # Interaction
        self.dragging_node = None
        self.panning = False
        self.last_mouse_pos = QPointF()
        
        # Physics Timer
        self.timer = QTimer(self)
        self.timer.timeout.connect(self.physics_loop)
        self.timer.start(16) # ~60 FPS
        
        self.setMouseTracking(True)

    def physics_loop(self):
        # Run physics step
        self.engine.step()
        # Request redraw
        self.update()

    def paintEvent(self, event):
        painter = QPainter(self)
        painter.setRenderHint(QPainter.RenderHint.Antialiasing)
        
        # Fill Background
        painter.fillRect(self.rect(), self.bg_color)
        
        # Apply Camera Transform
        transform = QTransform()
        center_x = self.width() / 2
        center_y = self.height() / 2
        
        transform.translate(center_x + self.offset_x, center_y + self.offset_y)
        transform.scale(self.scale, self.scale)
        painter.setTransform(transform)
        
        # Draw Edges
        pen = QPen(self.edge_color, 2)
        painter.setPen(pen)
        for u, v in self.engine.edges:
            n1 = self.engine.nodes.get(u)
            n2 = self.engine.nodes.get(v)
            if n1 and n2:
                # Draw Line
                p1 = QPointF(n1.x, n1.y)
                p2 = QPointF(n2.x, n2.y)
                painter.drawLine(p1, p2)

                # Draw Arrowhead
                # Calculate direction vector
                dx = n2.x - n1.x
                dy = n2.y - n1.y
                dist = math.sqrt(dx*dx + dy*dy)
                
                if dist > self.node_radius: # Only draw if nodes aren't overlapping
                    # Normalize
                    dx /= dist
                    dy /= dist
                    
                    # Point on the edge of the destination node
                    end_x = n2.x - dx * self.node_radius
                    end_y = n2.y - dy * self.node_radius
                    
                    # Arrow size
                    arrow_size = 8
                    
                    # Calculate arrow points
                    # Perpendicular vector (-dy, dx)
                    arrow_p1_x = end_x - dx * arrow_size + dy * (arrow_size * 0.5)
                    arrow_p1_y = end_y - dy * arrow_size - dx * (arrow_size * 0.5)
                    
                    arrow_p2_x = end_x - dx * arrow_size - dy * (arrow_size * 0.5)
                    arrow_p2_y = end_y - dy * arrow_size + dx * (arrow_size * 0.5)
                    
                    # Draw triangle
                    path = QPainterPath()
                    path.moveTo(end_x, end_y)
                    path.lineTo(arrow_p1_x, arrow_p1_y)
                    path.lineTo(arrow_p2_x, arrow_p2_y)
                    path.closeSubpath()
                    
                    painter.fillPath(path, self.edge_color)
        
        # Draw Nodes
        font = QFont("Segoe UI", 10)
        painter.setFont(font)
        
        for node in self.engine.nodes.values():
            # Determine color (maybe highlight if connected?)
            brush = QBrush(self.node_color)
            painter.setBrush(brush)
            painter.setPen(Qt.PenStyle.NoPen)
            
            # Draw Circle
            rect = QRectF(node.x - self.node_radius, node.y - self.node_radius, 
                          self.node_radius * 2, self.node_radius * 2)
            painter.drawEllipse(rect)
            
            # Draw Text
            painter.setPen(self.node_text_color)
            # Draw centered text (simplified)
            # For better visibility, maybe draw text outside or on top
            painter.drawText(rect, Qt.AlignmentFlag.AlignCenter, node.label[:4]) # Short label inside
            
            # Full label below
            painter.drawText(QRectF(node.x - 50, node.y + self.node_radius + 2, 100, 20), 
                             Qt.AlignmentFlag.AlignCenter, node.label)

    def mousePressEvent(self, event):
        mouse_pos = event.position()
        
        if event.button() == Qt.MouseButton.RightButton:
            self.panning = True
            self.last_mouse_pos = mouse_pos
            self.setCursor(Qt.CursorShape.ClosedHandCursor)
            return

        if event.button() == Qt.MouseButton.LeftButton:
            # Check for node click
            # Transform mouse to world space
            world_pos = self.screen_to_world(mouse_pos)
            
            for node in self.engine.nodes.values():
                dx = world_pos.x() - node.x
                dy = world_pos.y() - node.y
                if math.sqrt(dx*dx + dy*dy) <= self.node_radius:
                    self.dragging_node = node
                    self.setCursor(Qt.CursorShape.PointingHandCursor)
                    self.nodeClicked.emit(node.uid)
                    return

    def mouseMoveEvent(self, event):
        mouse_pos = event.position()
        
        if self.panning:
            delta = mouse_pos - self.last_mouse_pos
            self.offset_x += delta.x()
            self.offset_y += delta.y()
            self.last_mouse_pos = mouse_pos
            self.update()
            
        elif self.dragging_node:
            world_pos = self.screen_to_world(mouse_pos)
            self.dragging_node.x = world_pos.x()
            self.dragging_node.y = world_pos.y()
            # Zero velocity so it doesn't shoot off when released
            self.dragging_node.vx = 0
            self.dragging_node.vy = 0
            self.update()

    def mouseReleaseEvent(self, event):
        self.dragging_node = None
        self.panning = False
        self.setCursor(Qt.CursorShape.ArrowCursor)

    def wheelEvent(self, event):
        # Zoom
        angle = event.angleDelta().y()
        factor = 1.1 if angle > 0 else 0.9
        
        new_scale = self.scale * factor
        if self.min_scale <= new_scale <= self.max_scale:
            self.scale = new_scale
            self.update()

    def screen_to_world(self, screen_pos):
        # Invert the transform logic
        # screen = (world * scale) + offset + center
        # world = (screen - center - offset) / scale
        
        center_x = self.width() / 2
        center_y = self.height() / 2
        
        wx = (screen_pos.x() - center_x - self.offset_x) / self.scale
        wy = (screen_pos.y() - center_y - self.offset_y) / self.scale
        return QPointF(wx, wy)
