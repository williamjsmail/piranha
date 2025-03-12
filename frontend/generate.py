import matplotlib.pyplot as plt
from PyQt6.QtWidgets import (QMessageBox, QFileDialog, QTableWidgetItem, QGraphicsScene,
                QGraphicsScene, QGraphicsEllipseItem, QGraphicsLineItem, QGraphicsTextItem,
                QGraphicsItem, QDialog, QVBoxLayout, QLabel, QPushButton, QMenu)
from PyQt6.QtCore import Qt
from PyQt6.QtGui import QBrush, QPen, QFont, QTransform
from collections import defaultdict
from backend.processor import get_apt_report
from backend.export import save_to_excel
from backend.logging_config import logger
import networkx as nx
import matplotlib.pyplot as plt


def plot_graph(data):

    if not data:
        print("❌ No data provided to plot_graph()")
        return None

    # Create Graph
    G = nx.Graph()
    apts = {apt for apt, _ in data}
    tcodes = {tcode for _, tcode in data}

    G.add_nodes_from(apts, bipartite=0)
    G.add_nodes_from(tcodes, bipartite=1)
    G.add_edges_from(data)

    pos = nx.bipartite_layout(G, apts)

    # Determine shared T-codes
    tcode_counts = {tcode: sum(1 for _, tc in data if tc == tcode) for tcode in tcodes}

    node_colors = []
    for node in G.nodes():
        if node in apts:
            node_colors.append("lightblue")
        else:
            intensity = min(1.0, 0.3 + 0.7 * (tcode_counts[node] / max(tcode_counts.values())))
            node_colors.append((1, 0, 0, intensity))

    fig, ax = plt.subplots(figsize=(8, 5))
    nx.draw(G, pos, with_labels=True, node_size=2500, 
            node_color=node_colors, edge_color="gray", 
            font_size=10, font_weight="bold", ax=ax)
    ax.set_title("APT to T-Code Mapping")

    # Save graph to a file for debugging
    fig.savefig("debug_graph.png")  #  Save image for manual verification
    print(" Graph saved as debug_graph.png")

    # Convert matplotlib figure to QImage
    fig.canvas.draw()
    width, height = fig.canvas.get_width_height()
    img_data = fig.canvas.buffer_rgba()  # Get raw image data

    from PyQt6.QtGui import QImage, QPixmap
    qimage = QImage(img_data, width, height, QImage.Format.Format_ARGB32)
    pixmap = QPixmap.fromImage(qimage)

    plt.close(fig)

    # Create a QGraphicsScene and add the pixmap
    scene = QGraphicsScene()
    scene.addPixmap(pixmap)
    print(" Scene successfully created with defined size!")
    
    return scene



def generate_mitre_freq_table(output_data):
    if not output_data:
        QMessageBox.critical(None, "Error", "No report data available.")
        return


    tcode_counts = defaultdict(int)
    for row in output_data:
        t_code = row[2]
        tcode_counts[t_code] += 1


    sorted_tcodes = sorted(tcode_counts.items(), key=lambda x: x[1], reverse=True)


    labels, values = zip(*sorted_tcodes)
    fig, ax = plt.subplots(figsize=(10, 5))
    ax.barh(labels, values, color="grey")
    ax.set_xlabel("Usage Count")
    ax.set_title("MITRE ATT&CK Frequency Table (Most Used Techniques)")
    plt.show()


def generate_report(apt_listbox, tactic_listbox, TACTIC_MAPPING, include_description, use_enterprise, use_mobile, use_ics, include_detections, tree, graph_view):
    selected_apts = [apt_listbox.item(i).text() for i in range(apt_listbox.count()) if apt_listbox.item(i).isSelected()]
    selected_display_tactics = [tactic_listbox.item(i).text() for i in range(tactic_listbox.count()) if tactic_listbox.item(i).isSelected()]
    selected_tactics = [TACTIC_MAPPING[tactic] for tactic in selected_display_tactics]
    include_desc = include_description.isChecked()

    selected_datasets = {
        "enterprise": use_enterprise.isChecked(),
        "mobile": use_mobile.isChecked(),
        "ics": use_ics.isChecked()
    }

    logger.info(f"Selected APTs: {selected_apts}")
    logger.info(f"Selected Tactics (Human-readable): {selected_display_tactics}")
    logger.info(f"Converted Tactics (JSON names): {selected_tactics}")
    logger.info(f"Include T-Code Descriptions: {include_desc}")
    logger.info(f"Selected Datasets: {selected_datasets}")

    if not selected_apts:
        QMessageBox.critical(None, "Error", "Please select at least one APT.")
        return
    if not selected_tactics:
        QMessageBox.critical(None, "Error", "Please select at least one tactic.")
        return
    if not any(selected_datasets.values()):
        QMessageBox.critical(None, "Error", "Please select at least one dataset.")
        return

    include_mitre_detections = include_detections.isChecked()

    global output_data
    output_data = get_apt_report(
        selected_apts, selected_tactics, include_desc, selected_datasets, include_mitre_detections
    )

    apt_tcodes = [(row[0], row[2]) for row in output_data]  # Ensure correct structure

    if not output_data:
        logger.error("No data retrieved from backend.")
        QMessageBox.critical(None, "Error", "No data retrieved. Check the JSON file or tactic mappings.")
        return

    tree.setRowCount(0)
    for data in output_data:
        row_position = tree.rowCount()
        tree.insertRow(row_position)
        for col, value in enumerate(data):
            tree.setItem(row_position, col, QTableWidgetItem(str(value)))

    # Use InteractiveGraph instead of PNG
    graph_scene = InteractiveGraph(apt_tcodes)
    graph_view.setScene(graph_scene)
    graph_view.show()
    print(" Interactive graph updated!")




def export_to_excel(output_data, include_description, include_detections):
    if not output_data:
        QMessageBox.critical(None, "Error", "No data to export. Generate a report first.")
        return


    file_path, _ = QFileDialog.getSaveFileName(None, "Save Report", "", "Excel Files (*.xlsx);;All Files (*)")


    if file_path:
        include_desc = include_description.isChecked()
        save_to_excel(output_data, file_path, include_desc, include_detections.isChecked())
        QMessageBox.information(None, "Success", f"Data saved to {file_path}")



class InteractiveGraph(QGraphicsScene):
    def __init__(self, data, parent=None):
        super().__init__(parent)
        self.setSceneRect(-500, -500, 1000, 1000)  # Expand scene area for free movement
        self.G = nx.Graph()
        self.node_items = {}  # Stores nodes as QGraphicsEllipseItems
        self.edge_items = []  # Stores edge lines
        self.data = data

        self.create_graph(self.data)

    def create_graph(self, data):
        """Create an interactive APT-TCode graph using QGraphicsScene."""

        apts = set(apt for apt, _ in data)
        tcodes = set(tcode for _, tcode in data)

        self.G.add_nodes_from(apts)
        self.G.add_nodes_from(tcodes)
        self.G.add_edges_from(data)

        #  Adjust node spacing dynamically
        pos = nx.spring_layout(self.G, k=0.5, seed=42)  # Increase `k` to spread nodes out

        # Create nodes
        for node, (x, y) in pos.items():
            is_apt = node in apts  #  First value in data → APT (Blue)
            self.add_node(node, x * 400, y * 400, is_apt)

        # Create edges
        for src, dst in self.G.edges():
            self.add_edge(src, dst)

    def add_node(self, name, x, y, is_apt):
        """Assign blue to APTs and red to T-Codes based on the data structure."""
        node_color = Qt.GlobalColor.blue if is_apt else Qt.GlobalColor.red  #  Blue for APTs, Red for T-Codes

        node_item = DraggableNode(x, y, 30, name, node_color)
        self.addItem(node_item)
        self.node_items[name] = node_item

    def add_edge(self, src, dst):
        """Create and store an edge between two nodes."""
        if src in self.node_items and dst in self.node_items:
            src_item = self.node_items[src]
            dst_item = self.node_items[dst]
            edge = InteractiveEdge(src_item, dst_item)  #  Create edge
            self.addItem(edge)
            self.edge_items.append(edge)
    
    def contextMenuEvent(self, event):
        """Right-clicking outside of nodes shows filtering options. Right-clicking a node lets it handle its own menu."""
        clicked_item = self.itemAt(event.scenePos(), QTransform())  #  Detect if a node was clicked

        if isinstance(clicked_item, DraggableNode):
            clicked_item.contextMenuEvent(event)  #  Let the node handle its own right-click menu
            return

        #  If right-clicking on empty space, show filtering menu
        menu = QMenu()
        show_shared_action = menu.addAction("Show Only Shared T-Codes")
        restore_action = menu.addAction("Restore Full Graph")

        action = menu.exec(event.screenPos())

        if action == show_shared_action:
            self.show_only_shared_tcodes()
        elif action == restore_action:
            self.clear()
            self.node_items.clear()
            self.edge_items.clear()
            self.G.clear()
            self.create_graph(self.data)

    def show_only_shared_tcodes(self):
        """Modify the graph to display only shared T-Codes and remove all unrelated edges."""
        shared_tcodes = self.get_shared_tcodes()
        visible_apts = set()

        print(f"DEBUG: Shared T-Codes: {shared_tcodes}")  #  Debugging

        #  Identify APTs connected to shared T-Codes
        for src, dst in list(self.G.edges()):
            if dst in shared_tcodes:
                visible_apts.add(src)

        print(f"DEBUG: Visible APTs: {visible_apts}")  #  Debugging

        #  Hide all nodes that are not part of shared connections
        for node, item in self.node_items.items():
            if node in shared_tcodes or node in visible_apts:
                print(f"DEBUG: Keeping Node {node}")  #  Debugging
            else:
                print(f"DEBUG: Hiding Node {node}")  #  Debugging
                item.setVisible(False)  #  Hide non-shared nodes

        #  REMOVE edges that do not connect APTs to shared T-Codes
        to_remove = []  #  Track edges to remove
        for edge in self.edge_items[:]:  #  Copy list to avoid modification errors
            if not edge.src or not edge.dst:
                continue

            src_tooltip = edge.src.toolTip()
            dst_tooltip = edge.dst.toolTip()

            if src_tooltip in visible_apts and dst_tooltip in shared_tcodes:
                print(f"DEBUG: KEEP EDGE {src_tooltip} -> {dst_tooltip}")
            else:
                print(f"DEBUG: REMOVE EDGE {src_tooltip} -> {dst_tooltip}")  #  Debugging
                to_remove.append(edge)

        #  Remove edges from the scene
        for edge in to_remove:
            self.removeItem(edge)
            self.edge_items.remove(edge)

    def restore_original_graph(self):
        """Restore the original graph after filtering."""
        for item in self.items():
            item.setVisible(True)  #  Show everything again

    def get_shared_tcodes(self):
        """Find T-Codes that are connected to multiple APTs."""
        tcode_counts = {}

        for src, dst in self.G.edges():
            if dst.startswith("T"):  #  If the destination node is a T-Code
                tcode_counts[dst] = tcode_counts.get(dst, 0) + 1

        return [tcode for tcode, count in tcode_counts.items() if count > 1]

class InteractiveEdge(QGraphicsLineItem):
    """Edge that connects two nodes and updates dynamically."""
    def __init__(self, src, dst):
        super().__init__()
        self.setPen(QPen(Qt.GlobalColor.gray, 2))
        self.src = src
        self.dst = dst
        self.update_position()

        #  Register this edge with the connected nodes
        src.add_edge(self)
        dst.add_edge(self)

    def update_position(self):
        """Update the edge's position based on the node locations."""
        if not self.src or not self.dst:
            return

        src_pos = self.src.scenePos()
        dst_pos = self.dst.scenePos()
        
        self.setLine(
            src_pos.x() + self.src.rect().width() / 2, 
            src_pos.y() + self.src.rect().height() / 2,
            dst_pos.x() + self.dst.rect().width() / 2, 
            dst_pos.y() + self.dst.rect().height() / 2
        )
    
    def get_other_node(self, node):
        """Return the node on the opposite end of the edge."""
        return self.dst if node == self.src else self.src
    
    def delete_edge(self):
        """Remove edge from scene and notify nodes."""
        if self.src and self.dst:
            self.src.edges.remove(self)
            self.dst.edges.remove(self)

        self.scene().removeItem(self)


class DraggableNode(QGraphicsEllipseItem):
    """Interactive node that can be clicked, dragged, and hovered."""
    def __init__(self, x, y, size, name, color):
        super().__init__(0, 0, size, size)
        self.setBrush(QBrush(color))
        self.setPen(QPen(Qt.GlobalColor.black, 1))
        self.setFlags(QGraphicsEllipseItem.GraphicsItemFlag.ItemIsMovable | 
                      QGraphicsEllipseItem.GraphicsItemFlag.ItemIsSelectable)
        self.setToolTip(name)
        self.setPos(x, y)
        self.edges = []  #  Store connected edges

        #  Add text label positioning inside the node
        self.label = QGraphicsTextItem(name)
        self.label.setDefaultTextColor(Qt.GlobalColor.white)
        self.label.setFont(QFont("Arial", 8, QFont.Weight.Bold))
        self.label.setParentItem(self)
        self.update_label_position()
        self.setZValue(2)
        self.label.setZValue(3)

    def update_label_position(self):
        """Center label inside the node."""
        text_rect = self.label.boundingRect()
        self.label.setPos(self.rect().width() / 2 - text_rect.width() / 2, 
                          self.rect().height() / 2 - text_rect.height() / 2)

    def add_edge(self, edge):
        """Register an edge to update when the node moves."""
        self.edges.append(edge)

    def itemChange(self, change, value):
        """Detect node movement and update edges dynamically."""
        if change == QGraphicsItem.GraphicsItemChange.ItemPositionChange:
            for edge in self.edges:
                edge.update_position()  #  Ensure edges update in real-time
            self.update_label_position()

            #  Explicitly trigger scene update
            if self.scene():
                self.scene().update()

        return super().itemChange(change, value)
    
    def mouseReleaseEvent(self, event):
        """Ensure edges update when the node is released."""
        super().mouseReleaseEvent(event)
        
        for edge in self.edges:
            edge.update_position()  #  Ensure edges update after dragging
    
    def contextMenuEvent(self, event):
        """Right-click menu for nodes, ensuring full node coverage."""
        menu = QMenu()
        details_action = menu.addAction("View Details")
        delete_action = menu.addAction("Delete Node")

        action = menu.exec(event.screenPos())

        if action == details_action:
            self.show_node_info()
        elif action == delete_action:
            self.delete_node()

        event.accept()  #  Ensure event is fully processed

    def delete_node(self):
        """Remove the node and all connected edges. If a connected node has no other connections, delete it too."""
        scene = self.scene()

        #  Find nodes that were **only connected to this node**
        to_delete = []
        for edge in self.edges[:]:  # Copy list to avoid modification issues
            other_node = edge.get_other_node(self)
            if len(other_node.edges) == 1:  #  If the connected node had only 1 edge (this one)
                to_delete.append(other_node)

            edge.delete_edge()  #  Remove the edge

        #  Remove this node itself
        scene.removeItem(self)

        #  Remove orphaned nodes
        for node in to_delete:
            scene.removeItem(node)

    def show_node_info(self):
        """Display node information in a **styled QDialog**."""
        connected_nodes = [edge.get_other_node(self) for edge in self.edges]
        connections = "\n".join(node.toolTip() for node in connected_nodes)

        dialog = QDialog()
        dialog.setWindowTitle(f"Node Details - {self.toolTip()}")
        dialog.setFixedSize(300, 200)  #  Set dialog size
        layout = QVBoxLayout(dialog)

        title_label = QLabel(f"<b>Node:</b> {self.toolTip()}")
        title_label.setStyleSheet("font-size: 12px; color: white;")
        layout.addWidget(title_label)

        connection_label = QLabel("<b>Connected To:</b>")
        connection_label.setStyleSheet("font-size: 12px; color: white; margin-top: 12px;")
        layout.addWidget(connection_label)

        connection_text = QLabel(connections if connections else "No connections")
        connection_text.setStyleSheet("font-size: 12px; color: #AAAAAA;")
        layout.addWidget(connection_text)

        close_btn = QPushButton("Close")
        close_btn.setStyleSheet("background-color: #444; color: white; padding: 5px; border-radius: 5px;")
        close_btn.clicked.connect(dialog.accept)
        layout.addWidget(close_btn)

        dialog.setStyleSheet("background-color: #222; border-radius: 10px;")  #  Dark mode styling
        dialog.exec()
