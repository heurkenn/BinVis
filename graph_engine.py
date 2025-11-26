import math
import random

class Node:
    def __init__(self, uid, label, data=None):
        self.uid = uid
        self.label = label
        self.data = data or {}
        self.x = random.uniform(-100, 100)
        self.y = random.uniform(-100, 100)
        self.vx = 0
        self.vy = 0
        self.radius = 20
        self.mass = 1

class GraphEngine:
    def __init__(self):
        self.nodes = {} # uid -> Node
        self.edges = [] # (uid1, uid2)
        
        # Physics constants
        self.repulsion = 5000.0
        self.spring_length = 100.0
        self.spring_k = 0.05
        self.damping = 0.85
        self.center_attraction = 0.01

    def load_from_networkx(self, nx_graph):
        self.nodes = {}
        self.edges = []
        self.incoming = {} # uid -> [uids]
        self.outgoing = {} # uid -> [uids]
        
        for n, data in nx_graph.nodes(data=True):
            # Ensure unique ID (using name string as ID for now)
            self.nodes[n] = Node(n, n, data)
            self.incoming[n] = []
            self.outgoing[n] = []
            
        for u, v in nx_graph.edges():
            if u in self.nodes and v in self.nodes:
                self.edges.append((u, v))
                self.outgoing[u].append(v)
                self.incoming[v].append(u)

    def step(self, dt=0.016):
        """Updates node positions based on forces."""
        
        # Reset forces (we'll accumulate them in vx/vy directly for simplicity, 
        # treating mass=1, so F=a)
        # Actually better to compute forces separately then apply.
        forces = {uid: [0.0, 0.0] for uid in self.nodes}

        node_items = list(self.nodes.values())

        # 1. Repulsion (All vs All)
        # Optimization: Could use Quadtree for O(N log N), but O(N^2) is fine for small graphs (< 200 nodes)
        for i in range(len(node_items)):
            n1 = node_items[i]
            for j in range(i + 1, len(node_items)):
                n2 = node_items[j]
                
                dx = n1.x - n2.x
                dy = n1.y - n2.y
                dist_sq = dx*dx + dy*dy
                dist = math.sqrt(dist_sq)
                
                if dist < 1: dist = 1 # Avoid division by zero
                
                # F = k / dist^2
                f = self.repulsion / dist_sq
                
                fx = (dx / dist) * f
                fy = (dy / dist) * f
                
                forces[n1.uid][0] += fx
                forces[n1.uid][1] += fy
                forces[n2.uid][0] -= fx
                forces[n2.uid][1] -= fy

        # 2. Spring Attraction (Edges)
        for u, v in self.edges:
            n1 = self.nodes[u]
            n2 = self.nodes[v]
            
            dx = n2.x - n1.x
            dy = n2.y - n1.y
            dist = math.sqrt(dx*dx + dy*dy)
            
            # F = k * (current_dist - target_dist)
            displacement = dist - self.spring_length
            f = self.spring_k * displacement
            
            if dist == 0: dist = 0.1
            
            fx = (dx / dist) * f
            fy = (dy / dist) * f
            
            forces[n1.uid][0] += fx
            forces[n1.uid][1] += fy
            forces[n2.uid][0] -= fx
            forces[n2.uid][1] -= fy
            
        # 3. Center Gravity (Pull to 0,0)
        for n in node_items:
            forces[n.uid][0] -= n.x * self.center_attraction
            forces[n.uid][1] -= n.y * self.center_attraction

        # 4. Integration
        for n in node_items:
            fx, fy = forces[n.uid]
            
            n.vx = (n.vx + fx) * self.damping
            n.vy = (n.vy + fy) * self.damping
            
            n.x += n.vx
            n.y += n.vy
