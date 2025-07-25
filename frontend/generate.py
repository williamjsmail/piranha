from PyQt6.QtWidgets import (QApplication, QMessageBox, QFileDialog, QTableWidgetItem, QGraphicsScene,
                QGraphicsScene, QGraphicsEllipseItem, QGraphicsLineItem, QGraphicsTextItem,
                QGraphicsItem, QDialog, QVBoxLayout, QLabel, QPushButton, QMenu)
from PyQt6.QtCore import Qt, QThread, pyqtSignal
from PyQt6.QtGui import QBrush, QPen, QFont, QTransform
from collections import defaultdict
from math import pi
import pandas as pd
from matplotlib.backends.backend_qt5agg import FigureCanvasQTAgg as FigureCanvas
from matplotlib.figure import Figure
from backend.processor import get_apt_report, get_limited_apt_report
from backend.export import save_to_excel
from backend.loader import load_tcodes_for_cve, load_component_json
from backend.logging_config import logger
import networkx as nx
import matplotlib.pyplot as plt
import numpy as np
from mpl_toolkits.mplot3d import Axes3D
from mpl_toolkits.mplot3d.proj3d import proj_transform
from itertools import combinations

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

def plot_3d_bar_chart(heatmap_data):
    if not heatmap_data:
        logger.error("No data to plot.")
        return
    
    if len(heatmap_data["x"]) <= 5:
        logger.info("Small dataset - switching to 2D fallback view.")
        plot_2d_fallback(heatmap_data)
        return

    fig = plt.figure(figsize=(12, 8))
    ax = fig.add_subplot(111, projection='3d')

    # Extract values
    x = np.array(heatmap_data["x"])  # T-Code Frequency in Nessus Scan
    y = np.array(heatmap_data["y_mean"])  # Mean CVSS Score
    z = np.zeros(len(x))  # Bars start at Z=0

    # Heights of bars
    dz = np.array([max(1, val) for val in heatmap_data["z"]])  # Number of APTs

    num_bars = len(x)
    bar_width = 0.6 if len(x) == 1 else 5
    bar_depth = 0.3 if len(x) == 1 else 0.5
    dx = np.full(len(x), bar_width)
    dy = np.full(len(x), bar_depth)
    if len(x) == 1:
        x = x + 1
        y = y + 1

    # Use Piranha Weight for color mapping
    weights = np.array(heatmap_data["weights"])  # Extract Piranha Weights
    norm_weights = weights / max(weights)
    colors = plt.cm.turbo(norm_weights)

    # Plot solid rectangular bars
    bars = ax.bar3d(x, y, z, dx, dy, dz, color=colors, alpha=0.9, shade=True)

    if len(x) > 1:
        x_margin = (max(x) - min(x)) * 0.1
        y_margin = (max(y) - min(y)) * 0.1
        z_margin = (max(dz) - min(dz)) * 0.1

        ax.set_xlim(max(0, min(x) - x_margin), max(x) + x_margin)
        ax.set_ylim(max(0, min(y) - y_margin), max(y) + y_margin)
        ax.set_zlim(0, max(dz) + z_margin)
    else:
        # When only one data point exists
        ax.set_xlim(0, x[0] + 10)
        ax.set_ylim(0, y[0] + 1)
        ax.set_zlim(0, dz[0] + 1)

        ax.set_xlim(max(0, min(x) - x_margin), max(x) + x_margin)
        ax.set_ylim(max(0, min(y) - y_margin), max(y) + y_margin)
        ax.set_zlim(0, max(dz) + z_margin)

    # Labels and title
    ax.set_xlabel("T-Code Frequency in Nessus Scan")
    ax.set_ylabel("Mean CVSS Score")
    ax.set_zlabel("Number of APTs Using T-Code")
    ax.set_title("3D T-Code Heatmap (Hybrid CVSS: Mean & Max)")

    # Add color bar legend
    sm = plt.cm.ScalarMappable(cmap="turbo", norm=plt.Normalize(vmin=min(weights), vmax=max(weights)))
    cbar = plt.colorbar(sm, ax=ax, shrink=0.5, aspect=10, pad=0.1)
    cbar.set_label("Piranha Weight")

    # Hover text
    annot = ax.text2D(0.5, 0.95, "", transform=ax.transAxes, fontsize=10,
                      bbox=dict(boxstyle="round,pad=0.3", fc="white", ec="black", lw=2),
                      ha='center', color='black', visible=False)

    last_hovered_index = None

    def project_3d_to_2d(x, y, z):
        #Convert 3D coordinates to 2D
        x2d, y2d, _ = proj_transform(x, y, z, ax.get_proj())
        screen_coords = ax.transData.transform((x2d, y2d))
        return screen_coords

    def on_hover(event):
        nonlocal last_hovered_index

        if event.inaxes != ax:
            if last_hovered_index is not None:
                annot.set_visible(False)
                last_hovered_index = None
                fig.canvas.draw_idle()
            return

        # Track the closest bar to cursor
        min_dist = float('inf')
        closest_idx = None

        for i in range(len(x)):
            # Convert key bar points to 2D
            bar_points = [
                project_3d_to_2d(x[i], y[i], z[i]),                          # Bottom-left
                project_3d_to_2d(x[i] + dx[i], y[i], z[i]),                  # Bottom-right
                project_3d_to_2d(x[i], y[i] + dy[i], z[i]),                  # Front-left
                project_3d_to_2d(x[i] + dx[i], y[i] + dy[i], z[i]),          # Front-right
                project_3d_to_2d(x[i], y[i], z[i] + dz[i]),                  # Top-left
                project_3d_to_2d(x[i] + dx[i], y[i] + dy[i], z[i] + dz[i]),  # Top-right
            ]

            # Find the closest point on bar
            for point in bar_points:
                x_2d, y_2d = point
                dist = np.linalg.norm([event.x - x_2d, event.y - y_2d])

                if dist < min_dist:
                    min_dist = dist
                    closest_idx = i

        # Adjust hover sensitivity
        adaptive_threshold = max(10, min(50, dz[i] * 5)) if closest_idx is not None else 50

        # Update hover text
        if closest_idx is not None and min_dist < adaptive_threshold and closest_idx != last_hovered_index:
            tooltip_text = (
                f"{heatmap_data['labels'][closest_idx]}\n"
                f"Used by APTs: {heatmap_data['z'][closest_idx]}\n"
                f"Number of CVEs: {heatmap_data['x'][closest_idx]}\n"
                f"Mean CVSS: {heatmap_data['y_mean'][closest_idx]:.2f}\n"
                f"Max CVSS: {heatmap_data['y_max'][closest_idx]:.2f}\n"
                f"Piranha Weight: {heatmap_data['weights'][closest_idx]:.2f}"
            )

            annot.set_text(tooltip_text)
            annot.set_visible(True)
            annot.set_position((event.x / fig.bbox.width, 1 - event.y / fig.bbox.height))
            last_hovered_index = closest_idx
            fig.canvas.draw_idle()
        elif closest_idx is None and last_hovered_index is not None:
            annot.set_visible(False)
            last_hovered_index = None
            fig.canvas.draw_idle()

    fig.canvas.mpl_connect("motion_notify_event", on_hover)

    plt.show()

def plot_2d_fallback(data):
    import matplotlib.pyplot as plt
    from matplotlib.patches import Rectangle

    fig, ax = plt.subplots(figsize=(8, 5))
    x_labels = data["labels"]
    heights = data["weights"]
    colors = plt.cm.turbo(np.array(heights) / max(heights))
    bars = ax.bar(x_labels, heights, color=colors)

    ax.set_title("2D T-Code Bar Chart (Piranha Weights)")
    ax.set_ylabel("Piranha Weight")
    ax.set_xlabel("T-Code")
    plt.xticks(rotation=45, ha='right')
    plt.tight_layout()

    annot = ax.annotate(
        "", xy=(0, 0), xytext=(10, 10), textcoords="offset points",
        bbox=dict(boxstyle="round", fc="w", ec="black", lw=1),
        arrowprops=dict(arrowstyle="->"),
        ha='center'
    )
    annot.set_visible(False)

    def update_annot(bar, idx):
        t_code = x_labels[idx]
        tooltip_text = (
            f"{t_code}\n"
            f"Used by APTs: {data['z'][idx]}\n"
            f"Number of CVEs: {data['x'][idx]}\n"
            f"Mean CVSS: {data['y_mean'][idx]:.2f}\n"
            f"Max CVSS: {data['y_max'][idx]:.2f}\n"
            f"Piranha Weight: {data['weights'][idx]:.2f}"
        )
        annot.set_text(tooltip_text)
        annot.xy = (bar.get_x() + bar.get_width() / 2, bar.get_height())

    def hover(event):
        vis = annot.get_visible()
        if event.inaxes == ax:
            for idx, bar in enumerate(bars):
                if bar.contains(event)[0]:
                    update_annot(bar, idx)
                    annot.set_visible(True)
                    fig.canvas.draw_idle()
                    return
        if vis:
            annot.set_visible(False)
            fig.canvas.draw_idle()

    fig.canvas.mpl_connect("motion_notify_event", hover)

    plt.show()

def generate_heatmap(filtered_data, table_tcodes, apt_tcode_map, max_cves_display=5):
    if not filtered_data:
        logger.info("No relevant data found.")
        return

    tcode_freq = {}
    cvss_scores = {}
    associated_cves = {}
    apt_count = {}
    apt_tcode_map = {}
    for apt_name, _, t_code, *_ in output_data:
        if t_code:
            if t_code not in apt_tcode_map:
                apt_tcode_map[t_code] = set()
            apt_tcode_map[t_code].add(apt_name)

    # Process CVEs and map them to T-Codes
    for cve, cvss_score in filtered_data.items():
        t_codes = load_tcodes_for_cve(cve)

        formatted_t_codes = {f"T{t.strip()}" for t in t_codes}
        formatted_table_tcodes = {t.strip() for t in table_tcodes}

        relevant_tcodes = formatted_t_codes.intersection(formatted_table_tcodes)
        if not relevant_tcodes:
            continue

        for t_code in relevant_tcodes:
            # Track frequency of T-Codes
            tcode_freq[t_code] = tcode_freq.get(t_code, 0) + 1

            # Track highest CVSS and store all CVSS scores for mean calculation
            if t_code not in cvss_scores:
                cvss_scores[t_code] = {"max": cvss_score, "all_scores": [cvss_score]}
            else:
                cvss_scores[t_code]["max"] = max(cvss_scores[t_code]["max"], cvss_score)
                cvss_scores[t_code]["all_scores"].append(cvss_score)

            # Track associated CVEs
            associated_cves.setdefault(t_code, []).append(cvss_score)

    for t_code in tcode_freq.keys():
        apt_count[t_code] = len(apt_tcode_map.get(t_code, set()))  # Get unique APTs using this T-Code

    if not tcode_freq:
        logger.info("No relevant data to plot.")
        return None
    
    weights = []
    for t_code in tcode_freq.keys():
        freq = tcode_freq[t_code]
        cvss_score = cvss_scores[t_code]["max"] / 10  # Normalize CVSS
        num_apts = max(apt_count.get(t_code, 0), 1)  # Avoid zero division
        weight = freq * cvss_score * (num_apts ** 0.5)
        weights.append(weight)

    # Compute Mean CVSS for each T-Code
    y_mean = [np.mean(cvss_scores[t_code]["all_scores"]) for t_code in tcode_freq.keys()]
    y_max = [cvss_scores[t_code]["max"] for t_code in tcode_freq.keys()]

    # Prepare heatmap data
    return {
        "x": list(tcode_freq.values()),  # Frequency of each T-Code
        "y_mean": y_mean,  # Mean CVSS Score
        "y_max": y_max,  # Max CVSS Score
        "z": [apt_count.get(t_code, 0) for t_code in tcode_freq.keys()],
        "weights": weights,  # Scale weight dynamically
        "labels": list(tcode_freq.keys())  # List of T-Code names
    }

#def generate_report(apt_listbox, tactic_listbox, TACTIC_MAPPING, include_description, use_enterprise, use_mobile, use_ics, include_detections, tree, graph_view):
def generate_report(
    apt_listbox, tactic_listbox, TACTIC_MAPPING, include_description,
    use_enterprise, use_mobile, use_ics, include_detections,
    tree, graph_view,
    radar_fig=None, radar_canvas=None, radar_summary=None, radar_tables=None
):
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
    output_data, data_components = get_apt_report(
        selected_apts, selected_tactics, include_desc, selected_datasets, include_mitre_detections
    )

    host_col_count = 0
    net_col_count = 0
    host_int_count = 0
    mem_an_count = 0

    data_comp_mapping = load_component_json()

    for tech_comps in data_components:
        for comp in data_components[tech_comps]:
            if comp in data_comp_mapping:
                if "Host Collection" in data_comp_mapping[comp]:
                    host_col_count += 1
                elif "Network Collection" in data_comp_mapping[comp]:
                    net_col_count += 1
                elif "Host Interrogation" in data_comp_mapping[comp]:
                    host_int_count += 1
                elif "Host Memory Analysis" in data_comp_mapping[comp]:
                    mem_an_count += 1
            else:
                logger.warning(f"{comp} not found")

    #full_count = host_col_count + net_col_count + host_int_count + mem_an_count

    if radar_fig and radar_canvas and radar_summary and radar_tables:
        plot_radar_chart(
            data_components,
            radar_fig,
            radar_canvas,
            radar_summary,
            radar_tables
        )
    
    apt_tcodes = [(row[0], row[2]) for row in output_data]

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

    graph_scene = InteractiveGraph(apt_tcodes)
    graph_view.setScene(graph_scene)
    graph_view.show()
    logger.info("Interactive graph updated!")
    return output_data

def plot_radar_chart(data_components, fig, canvas, summary_box, category_tables):
    categorized_data = load_component_json()

    # Count category presence
    category_counts = {
        "Network Collection": 0, #right side
        "Host Interrogation": 0, #top
        "Host Collection": 0, #left side
        "Host Memory Analysis": 0 #bottom
    }
    tcode_per_category = {
        "Host Collection": set(),
        "Network Collection": set(),
        "Host Interrogation": set(),
        "Host Memory Analysis": set()
    }

    for t_code, comps in data_components.items():
        for comp in comps:
            for cat in categorized_data.get(comp, []):
                category_counts[cat] += 1
                tcode_per_category[cat].add(t_code)

    total = sum(category_counts.values()) or 1  # prevent division by zero

    # Radar data setup
    labels = list(category_counts.keys())
    values = [category_counts[label] / total * 100 for label in labels]
    ideal_values = [20, 30, 40, 10] #network collection, host int, host collection, mem analysis

    angles = np.linspace(0, 2 * np.pi, len(labels), endpoint=False).tolist()
    values += values[:1]
    ideal_values += ideal_values[:1]
    angles += angles[:1]

    fig.clear()
    ax = fig.add_subplot(111, polar=True)
    ax.plot(angles, values, linewidth=2, linestyle='solid', label='Current')
    ax.fill(angles, values, alpha=0.3)

    ax.plot(angles, ideal_values, linestyle='dashed', color='red', label='Ideal')
    ax.fill(angles, ideal_values, alpha=0.1, color='red')

    ax.set_thetagrids(np.degrees(angles[:-1]), labels)
    ax.set_ylim(0, 75)
    #ax.set_title("Technique Coverage by Category", size=16)
    ax.legend(loc='upper right')
    canvas.draw()

    # Update summary box
    summary = "\n".join(f"{k}: {category_counts[k]} ({(category_counts[k]/total)*100:.1f}%)" for k in category_counts)
    summary_box.setText(summary)

    # Update category tables
    for cat, table in category_tables.items():
        table.setRowCount(len(tcode_per_category[cat]))
        for i, tcode in enumerate(sorted(tcode_per_category[cat])):
            table.setItem(i, 0, QTableWidgetItem(tcode))

def export_to_excel(output_data, include_description, include_detections):
    if not output_data:
        QMessageBox.critical(None, "Error", "No data to export. Generate a report first.")
        return

    file_path, _ = QFileDialog.getSaveFileName(None, "Save Report", "", "Excel Files (*.xlsx);;All Files (*)")

    if file_path:
        include_desc = include_description.isChecked()
        save_to_excel(output_data, file_path, include_desc, include_detections.isChecked())
        QMessageBox.information(None, "Success", f"Data saved to {file_path}")

class TacticOptimizationThread(QThread):
    finished = pyqtSignal(tuple, float, dict)  # Best combo, best score, best dist

    def __init__(self, apt_listbox, TACTIC_MAPPING, tactic_listbox, num_tactics, ideal_fit, excluded_tactics, mitre_data, component_map):
        super().__init__()
        self.apt_listbox = apt_listbox
        self.TACTIC_MAPPING = TACTIC_MAPPING
        self.tactic_listbox = tactic_listbox
        self.num_tactics = num_tactics
        self.ideal_fit = ideal_fit
        self.excluded_tactics = excluded_tactics
        self.mitre_data = mitre_data
        self.component_map = component_map

    def run(self):
        selected_apts = [self.apt_listbox.item(i).text() for i in range(self.apt_listbox.count()) if self.apt_listbox.item(i).isSelected()]
        selected_tactics = [self.tactic_listbox.item(i).text() for i in range(self.tactic_listbox.count())]
        tactics = [self.TACTIC_MAPPING[tac] for tac in selected_tactics]
        ex_tactics = [self.TACTIC_MAPPING[tac] for tac in self.excluded_tactics]
        for ex_tactic in ex_tactics:
            tactics.remove(ex_tactic)

        best_combo = None
        best_score = float('inf')
        best_dist = None

        for combo in combinations(tactics, self.num_tactics):
            output_data, data_components = get_limited_apt_report(
                selected_apts, combo, {"enterprise": True}
            )

            # Calculate radar profile
            category_counts = {"Host Collection": 0, "Network Collection": 0, "Host Interrogation": 0, "Host Memory Analysis": 0}
            total = 0
            for comps in data_components.values():
                for comp in comps:
                    for cat in self.component_map.get(comp, []):
                        category_counts[cat] += 1
                        total += 1

            if total == 0:
                continue

            dist = {k: v / total for k, v in category_counts.items()}
            score = np.std([dist.get(k, 0) - self.ideal_fit[k] for k in self.ideal_fit])

            if score < best_score:
                best_score = score
                best_combo = combo
                best_dist = dist

        self.finished.emit(best_combo, best_score, best_dist)

class InteractiveGraph(QGraphicsScene):
    def __init__(self, data, parent=None):
        super().__init__(parent)
        self.setSceneRect(-500, -500, 1000, 1000)  # Expand scene area for free movement
        self.G = nx.Graph()
        self.node_items = {}
        self.edge_items = []
        self.data = data

        self.create_graph(self.data)

    def create_graph(self, data):
        apts = set(apt for apt, _ in data)
        tcodes = set(tcode for _, tcode in data)

        self.G.add_nodes_from(apts)
        self.G.add_nodes_from(tcodes)
        self.G.add_edges_from(data)

        # Adjust node spacing dynamically
        pos = nx.spring_layout(self.G, k=0.75, seed=42)  # Increase k to spread nodes out

        # Create nodes
        for node, (x, y) in pos.items():
            is_apt = node in apts
            self.add_node(node, x * 400, y * 400, is_apt)

        # Create edges
        for src, dst in self.G.edges():
            self.add_edge(src, dst)

    def add_node(self, name, x, y, is_apt):
        node_color = Qt.GlobalColor.blue if is_apt else Qt.GlobalColor.red  # Blue for APTs, Red for T-Codes

        node_item = DraggableNode(x, y, 30, name, node_color)
        self.addItem(node_item)
        self.node_items[name] = node_item

    def add_edge(self, src, dst):
        if src in self.node_items and dst in self.node_items:
            src_item = self.node_items[src]
            dst_item = self.node_items[dst]
            edge = InteractiveEdge(src_item, dst_item)  # Create edge
            self.addItem(edge)
            self.edge_items.append(edge)
    
    def contextMenuEvent(self, event):
        clicked_item = self.itemAt(event.scenePos(), QTransform())  # Detect if a node was clicked

        if isinstance(clicked_item, DraggableNode):
            clicked_item.contextMenuEvent(event)  # Let the node handle its own right click menu
            return

        # If right clicking on empty space, show filtering menu
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
        shared_tcodes = self.get_shared_tcodes()
        visible_apts = set()

        #  Identify APTs connected to shared T-Codes
        for src, dst in list(self.G.edges()):
            if dst in shared_tcodes:
                visible_apts.add(src)

        #  Hide all nodes that are not part of shared connections
        for node, item in self.node_items.items():
            if node in shared_tcodes or node in visible_apts:
                continue
            else:
                item.setVisible(False)  #  Hide non-shared nodes

        #  Remove edges that do not connect APTs to shared T-Codes
        to_remove = []  #  Track edges to remove
        for edge in self.edge_items[:]:
            if not edge.src or not edge.dst:
                continue

            src_tooltip = edge.src.toolTip()
            dst_tooltip = edge.dst.toolTip()

            if src_tooltip in visible_apts and dst_tooltip in shared_tcodes:
                continue
            else:
                to_remove.append(edge)

        #  Remove edges from the scene
        for edge in to_remove:
            self.removeItem(edge)
            self.edge_items.remove(edge)

    def restore_original_graph(self):
        for item in self.items():
            item.setVisible(True)  #  Show everything again

    def get_shared_tcodes(self):
        tcode_counts = {}

        for src, dst in self.G.edges():
            if dst.startswith("T"):  #  If the destination node is a T-Code
                tcode_counts[dst] = tcode_counts.get(dst, 0) + 1

        return [tcode for tcode, count in tcode_counts.items() if count > 1]
    
    def mousePressEvent(self, event):
        clicked_item = self.itemAt(event.scenePos(), QTransform())  # Check if something was clicked

        if not isinstance(clicked_item, DraggableNode):
            self.reset_all_edges()  # Reset edges if clicking outside any node

        super().mousePressEvent(event)
    
    def reset_all_edges(self):
        for edge in self.edge_items:
            edge.highlight(False)  # Reset edges

class InteractiveEdge(QGraphicsLineItem):
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
        return self.dst if node == self.src else self.src
    
    def delete_edge(self):
        if self.src and self.dst:
            self.src.edges.remove(self)
            self.dst.edges.remove(self)

        self.scene().removeItem(self)
    
    def highlight(self, enable):
        if enable:
            self.setPen(QPen(Qt.GlobalColor.yellow, 3))  # Highlight color
        else:
            self.setPen(QPen(Qt.GlobalColor.gray, 2))  # Default color

class DraggableNode(QGraphicsEllipseItem):
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
        text_rect = self.label.boundingRect()
        self.label.setPos(self.rect().width() / 2 - text_rect.width() / 2, 
                          self.rect().height() / 2 - text_rect.height() / 2)

    def add_edge(self, edge):
        self.edges.append(edge)

    def itemChange(self, change, value):
        if change == QGraphicsItem.GraphicsItemChange.ItemPositionChange:
            for edge in self.edges:
                edge.update_position()  #  Ensure edges update in real-time
            self.update_label_position()

            if self.scene():
                self.scene().update()

        return super().itemChange(change, value)
    
    def mouseReleaseEvent(self, event):
        super().mouseReleaseEvent(event)
        for edge in self.edges:
            edge.update_position()
    
    def contextMenuEvent(self, event):
        menu = QMenu()
        details_action = menu.addAction("View Details")
        delete_action = menu.addAction("Delete Node")

        action = menu.exec(event.screenPos())

        if action == details_action:
            self.show_node_info()
        elif action == delete_action:
            self.delete_node()

        event.accept()

    def delete_node(self):
        scene = self.scene()

        to_delete = []
        for edge in self.edges[:]:
            other_node = edge.get_other_node(self)
            if len(other_node.edges) == 1:
                to_delete.append(other_node)

            edge.delete_edge()

        scene.removeItem(self)

        # Remove orphaned nodes
        for node in to_delete:
            scene.removeItem(node)

    def show_node_info(self):
        connected_nodes = [edge.get_other_node(self) for edge in self.edges]
        connections = "\n".join(node.toolTip() for node in connected_nodes)

        dialog = QDialog()
        dialog.setWindowTitle(f"Node Details - {self.toolTip()}")
        dialog.setFixedSize(300, 200)
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

        dialog.setStyleSheet("background-color: #222; border-radius: 10px;")
        dialog.exec()

    def mousePressEvent(self, event):
        self.scene().reset_all_edges()  # Reset all edges before highlighting
        for edge in self.edges:
            edge.highlight(True)  # Highlight edges
        super().mousePressEvent(event)
