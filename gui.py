# gui.py
import tkinter as tk
from tkinter import ttk, messagebox, filedialog
import json
import threading
import matplotlib.pyplot as plt
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg
import time
import os
import psutil
from datetime import datetime

from router_core import VirtualRouter

# Import NetworkMap
try:
    from network_map import NetworkMap
except ImportError:
    # Will display warning only when network map feature is used
    pass

class RouterGUI:
    def toggle_firewall(self):
        if not hasattr(self.router, "firewall"):
            messagebox.showerror("Error", "Firewall module not found.")
            return

        enabled = not self.router.firewall.is_enabled()
        self.router.firewall.set_enabled(enabled)
        status = "enabled" if enabled else "disabled"
        messagebox.showinfo("Firewall", f"Firewall {status}.")
        self.router.log_event(f"Firewall {status.upper()} by user.")

    def reset_firewall_hits(self):
        if not hasattr(self.router, "firewall"):
            messagebox.showerror("Error", "Firewall module not found.")
            return

        self.router.firewall.reset_hit_counts()
        messagebox.showinfo("Firewall", "Firewall hit counts reset.")
        self.router.log_event("Firewall hit counts reset by user.")

    def set_sniffing_interface(self):
        interface = self.interface_combo.get()
        if interface:
            self.router.set_sniffing_interface(interface)
            messagebox.showinfo("Interface Set", f"Sniffing on: {interface}")
        else:
            messagebox.showwarning("Warning", "Please select a valid interface.")

    def __init__(self, root):
        self.root = root
        self.root.title("Virtual Router")
        self.root.geometry("1200x800")
        self.root.configure(bg="#f0f8ff")  # Light blue background
        
        current_dir = os.path.dirname(os.path.abspath(__file__))
        routing_table_path = os.path.join(current_dir, "routing_table.json")
        self.router = VirtualRouter(routing_table_path=routing_table_path)
        self.router_thread = None
        self.loss_simulation_on = True
        self.dark_mode = False  # Light by default

        # Setup main layout
        self.setup_main_frame()
        self.setup_controls()
        self.setup_theme_toggle()
        self.setup_panes()

        self.update_routing_table()
        self.start_updates()

    def setup_main_frame(self):
        self.main_frame = ttk.Frame(self.root)
        self.main_frame.pack(fill=tk.BOTH, expand=True)

    def setup_controls(self):
        # Controls frame under main_frame
        self.controls_frame = ttk.Frame(self.main_frame)
        self.controls_frame.pack(fill=tk.X, pady=5, padx=5)

        # Left side controls (Start, Stop, Export, Reset, Loss Sim, TTL)
        left_controls = ttk.Frame(self.controls_frame)
        left_controls.pack(side=tk.LEFT, fill=tk.X, expand=True)

        row1 = ttk.Frame(left_controls)
        row1.pack(fill=tk.X, pady=2)

        self.start_button = ttk.Button(row1, text="Start Router", command=self.start_router)
        self.start_button.pack(side=tk.LEFT, padx=5)

        self.stop_button = ttk.Button(row1, text="Stop Router", command=self.stop_router, state=tk.DISABLED)
        self.stop_button.pack(side=tk.LEFT, padx=5)

        ttk.Button(row1, text="Export Packets", command=self.export_packets).pack(side=tk.LEFT, padx=5)
        ttk.Button(row1, text="Reset Stats", command=self.reset_stats).pack(side=tk.LEFT, padx=5)
        ttk.Button(row1, text="Toggle Loss Sim", command=self.toggle_loss_sim).pack(side=tk.LEFT, padx=5)
        ttk.Button(row1, text="Network Map", command=self.show_network_map).pack(side=tk.LEFT, padx=5)
        ttk.Button(row1, text="Firewall Manager", command=self.open_firewall_manager).pack(side=tk.LEFT, padx=5)


        # TTL Controls
        row2 = ttk.Frame(left_controls)
        row2.pack(fill=tk.X, pady=2)

        ttk.Label(row2, text="TTL Min:").pack(side=tk.LEFT, padx=5)
        self.ttl_min_entry = ttk.Entry(row2, width=5)
        self.ttl_min_entry.pack(side=tk.LEFT)

        ttk.Label(row2, text="TTL Max:").pack(side=tk.LEFT, padx=5)
        self.ttl_max_entry = ttk.Entry(row2, width=5)
        self.ttl_max_entry.pack(side=tk.LEFT)
# --- Firewall Controls ---
        row3 = ttk.Frame(left_controls)
        row3.pack(fill=tk.X, pady=2)

        ttk.Button(row3, text="Toggle Firewall", command=self.toggle_firewall).pack(side=tk.LEFT, padx=5)
        ttk.Button(row3, text="Reset Firewall Hits", command=self.reset_firewall_hits).pack(side=tk.LEFT, padx=5)


        # Right side controls (Interface selection)
        right_controls = ttk.Frame(self.controls_frame)
        right_controls.pack(side=tk.RIGHT, fill=tk.Y)

        ttk.Label(right_controls, text="Sniff Interface:").pack(side=tk.LEFT)

        self.interface_combo = ttk.Combobox(right_controls, values=list(psutil.net_if_addrs().keys()))
        self.interface_combo.pack(side=tk.LEFT, padx=5)

        if self.interface_combo['values']:
            self.interface_combo.set(self.interface_combo['values'][0])

        ttk.Button(right_controls, text="Set", command=self.set_sniffing_interface).pack(side=tk.LEFT)

    def open_firewall_manager(self):
        try:
            from firewall_manager_popup import FirewallManagerPopup
            FirewallManagerPopup(self.root, self.router.firewall)
        except Exception as e:
            messagebox.showerror("Error", f"Failed to open Firewall Manager.\n{e}")


    def setup_theme_toggle(self):
        theme_frame = ttk.Frame(self.main_frame)
        theme_frame.pack(fill=tk.X, pady=5)

        self.theme_button = ttk.Button(theme_frame, text="Toggle Theme", command=self.toggle_theme)
        self.theme_button.pack(side=tk.LEFT, padx=5)

        self.theme_status_label = ttk.Label(theme_frame, text="Light Mode Active")
        self.theme_status_label.pack(side=tk.LEFT, padx=10)

    def setup_panes(self):
        # Create PanedWindow under controls + theme toggle
        self.paned_window = tk.PanedWindow(self.main_frame, orient=tk.HORIZONTAL, sashwidth=4, sashrelief=tk.RAISED)
        self.paned_window.pack(fill=tk.BOTH, expand=True)

        # Left Frame - Routing Table
        self.left_frame = ttk.Frame(self.paned_window)
        self.paned_window.add(self.left_frame, stretch="always")
        self.setup_routing_table()

        # Right Frame - Statistics and Logs
        self.right_frame = ttk.Frame(self.paned_window)
        self.paned_window.add(self.right_frame, stretch="always")

        # Right side split vertically
        self.right_paned = tk.PanedWindow(self.right_frame, orient=tk.VERTICAL, sashwidth=4, sashrelief=tk.RAISED)
        self.right_paned.pack(fill=tk.BOTH, expand=True)

        self.stats_frame = ttk.LabelFrame(self.right_paned, text="Statistics")
        self.right_paned.add(self.stats_frame, stretch="always")
        self.setup_statistics()

        self.logs_frame = ttk.LabelFrame(self.right_paned, text="Logs")
        self.right_paned.add(self.logs_frame, stretch="always")
        self.setup_logs()

    def setup_routing_table(self):
        frame = ttk.LabelFrame(self.left_frame, text="Routing Table")
        frame.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)

        search_frame = ttk.Frame(frame)
        search_frame.pack(fill=tk.X, padx=5, pady=5)
        ttk.Label(search_frame, text="Search:").pack(side=tk.LEFT)
        self.search_entry = ttk.Entry(search_frame)
        self.search_entry.pack(side=tk.LEFT, fill=tk.X, expand=True)
        self.search_entry.bind("<KeyRelease>", self.filter_routing_table)

        tree_frame = ttk.Frame(frame)
        tree_frame.pack(fill=tk.BOTH, expand=True)

        columns = ("Destination", "Subnet", "Next Hop", "Interface", "Priority", "Cost", "Last Used")
        self.routing_tree = ttk.Treeview(tree_frame, columns=columns, show="headings")
        for col in columns:
            self.routing_tree.heading(col, text=col)
            self.routing_tree.column(col, width=100, minwidth=50)
        self.routing_tree.pack(fill=tk.BOTH, expand=True)

        scrollbar = ttk.Scrollbar(tree_frame, orient="vertical", command=self.routing_tree.yview)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        self.routing_tree.configure(yscrollcommand=scrollbar.set)

        # 🚀 Scrollable Buttons Frame
        button_container = ttk.Frame(frame)
        button_container.pack(fill=tk.X, pady=5)

        button_canvas = tk.Canvas(button_container, height=40)
        button_canvas.pack(side=tk.LEFT, fill=tk.X, expand=True)

        button_scrollbar = ttk.Scrollbar(button_container, orient="horizontal", command=button_canvas.xview)
        button_scrollbar.pack(side=tk.BOTTOM, fill=tk.X)

        button_frame = ttk.Frame(button_canvas)
        button_canvas.create_window((0, 0), window=button_frame, anchor="nw")

        button_canvas.configure(xscrollcommand=button_scrollbar.set)

        button_frame.bind(
            "<Configure>",
            lambda e: button_canvas.configure(scrollregion=button_canvas.bbox("all"))
        )

        # Buttons
        ttk.Button(button_frame, text="Add Route", command=self.add_route_popup).pack(side=tk.LEFT, padx=5)
        ttk.Button(button_frame, text="Add Default Route", command=self.add_default_route_popup).pack(side=tk.LEFT, padx=5)
        ttk.Button(button_frame, text="Delete Route", command=self.delete_route).pack(side=tk.LEFT, padx=5)
        ttk.Button(button_frame, text="Export Routes", command=self.export_routes).pack(side=tk.LEFT, padx=5)
        ttk.Button(button_frame, text="Import Routes", command=self.import_routes).pack(side=tk.LEFT, padx=5)
        ttk.Button(button_frame, text="Refresh Table", command=self.update_routing_table).pack(side=tk.LEFT, padx=5)
        ttk.Button(button_frame, text="View Network Map", command=self.show_network_map).pack(side=tk.LEFT, padx=5)

    def setup_statistics(self):
        stats_container = ttk.Frame(self.stats_frame)
        stats_container.pack(fill=tk.X, padx=10, pady=5)

        self.stats_labels = {}
        stats_fields = ["forwarded", "dropped", "ttl_expired", "source_invalid", "no_route", "total_processed"]
        for stat in stats_fields:
            row = ttk.Frame(stats_container)
            row.pack(fill=tk.X, pady=2)
            ttk.Label(row, text=stat.replace("_", " ").title() + ":").pack(side=tk.LEFT)
            self.stats_labels[stat] = ttk.Label(row, text="0")
            self.stats_labels[stat].pack(side=tk.RIGHT)

        # Packet types
        pkt_types = ["ICMP", "TCP", "UDP", "ARP", "Other"]
        self.packet_type_labels = {}
        pkt_frame = ttk.LabelFrame(self.stats_frame, text="Packet Types")
        pkt_frame.pack(fill=tk.X, padx=10, pady=5)
        for pkt_type in pkt_types:
            row = ttk.Frame(pkt_frame)
            row.pack(fill=tk.X, pady=2)
            ttk.Label(row, text=pkt_type + ":").pack(side=tk.LEFT)
            self.packet_type_labels[pkt_type] = ttk.Label(row, text="0")
            self.packet_type_labels[pkt_type].pack(side=tk.RIGHT)

        # Pie chart
        self.chart_frame = ttk.Frame(self.stats_frame)
        self.chart_frame.pack(fill=tk.BOTH, expand=True)
        self.fig, self.ax = plt.subplots(figsize=(4, 4), tight_layout=True)
        self.canvas = FigureCanvasTkAgg(self.fig, master=self.chart_frame)
        self.canvas.get_tk_widget().pack(fill=tk.BOTH, expand=True)
    
    def setup_logs(self):
        frame = ttk.Frame(self.logs_frame)
        frame.pack(fill=tk.BOTH, expand=True)

        self.log_text = tk.Text(frame, wrap='none')
        self.log_text.pack(fill=tk.BOTH, expand=True)

        y_scroll = ttk.Scrollbar(frame, orient="vertical", command=self.log_text.yview)
        y_scroll.pack(side=tk.RIGHT, fill=tk.Y)
        self.log_text.configure(yscrollcommand=y_scroll.set)

    def start_router(self):
        try:
            ttl_min = int(self.ttl_min_entry.get() or 32)
            ttl_max = int(self.ttl_max_entry.get() or 64)
            if not (1 <= ttl_min <= 255 and 1 <= ttl_max <= 255 and ttl_min < ttl_max):
                raise ValueError()
        except:
            messagebox.showerror("Error", "Invalid TTL values. Using default 32-64.")
            ttl_min = 32
            ttl_max = 64

        self.router.ttl_min = ttl_min
        self.router.ttl_max = ttl_max

        self.router_thread = threading.Thread(target=self.router.start, daemon=True)
        self.router_thread.start()
        self.start_button.config(state=tk.DISABLED)
        self.stop_button.config(state=tk.NORMAL)

    def stop_router(self):
        self.router.stop()
        self.start_button.config(state=tk.NORMAL)
        self.stop_button.config(state=tk.DISABLED)

    def start_updates(self):
        def update():
            self.update_statistics()
            self.update_logs()
            self.update_graph()
            self.root.after(2000, update)
        update()

    def update_statistics(self):
        stats = self.router.get_stats()
        for k, v in stats.items():
            if k in self.stats_labels:
                self.stats_labels[k].config(text=str(v))
        pkt_types = stats.get("packet_types", {})
        for pkt_type, label in self.packet_type_labels.items():
            label.config(text=str(pkt_types.get(pkt_type, 0)))

    def update_logs(self):
        logs = self.router.get_logs()
        self.log_text.delete(1.0, tk.END)
        for log in logs[-100:]:
            self.log_text.insert(tk.END, log + "\n")
        self.log_text.see(tk.END)
    
    def add_route_popup(self):
        try:
            from add_route_popup import AddRoutePopup
            AddRoutePopup(self.root, self.router, self.update_routing_table)
        except Exception as e:
            messagebox.showerror("Error", f"Failed to open Add Route Popup.\n{e}")

    def add_default_route_popup(self):
        try:
            from add_default_route_popup import AddDefaultRoutePopup
            AddDefaultRoutePopup(self.root, self.router, self.update_routing_table)
        except Exception as e:
            messagebox.showerror("Error", f"Failed to open Add Default Route Popup.\n{e}")

    def delete_route(self):
        selection = self.routing_tree.selection()
        if not selection:
            messagebox.showwarning("Warning", "Select a route first!")
            return
        values = self.routing_tree.item(selection[0])['values']
        destination, subnet = values[0], values[1]
        self.router.delete_route(destination, subnet)
        self.update_routing_table()
    
    def export_routes(self):
        file = filedialog.asksaveasfilename(defaultextension=".json")
        if file:
            with open(file, 'w') as f:
                json.dump(self.router.routing_table, f, indent=4)
            messagebox.showinfo("Export", "Routes exported successfully.")

    def import_routes(self):
        file = filedialog.askopenfilename(filetypes=[("JSON files", "*.json")])
        if file:
            with open(file, 'r') as f:
                self.router.routing_table = json.load(f)
            self.router.save_routing_table()
            self.update_routing_table()

    def update_graph(self):
        stats = self.router.get_stats()
        clean_stats = {k: v for k, v in stats.items() if k not in ["packet_types", "total_processed"]}
        labels = list(clean_stats.keys())
        sizes = list(clean_stats.values())

        self.ax.clear()

        # Filter out very small slices
        labels_filtered = []
        sizes_filtered = []
        for label, size in zip(labels, sizes):
            if size > 0:  # only keep non-zero slices
                labels_filtered.append(label)
                sizes_filtered.append(size)

        if sum(sizes_filtered) > 0:
            wedges, texts, autotexts = self.ax.pie(
                sizes_filtered,
                labels=labels_filtered,
                autopct=lambda pct: ('%1.1f%%' % pct) if pct > 1 else '',
                startangle=140,
                textprops={'fontsize': 8}
            )
            # Make inside numbers smaller if needed
            for autotext in autotexts:
                autotext.set_fontsize(7)
        else:
            self.ax.text(0.5, 0.5, "No Packets Yet", ha="center", va="center")

        self.ax.set_title("Packet Distribution", fontsize=10)
        self.fig.tight_layout()
        self.canvas.draw()

    def reset_stats(self):
        self.router.stats = {
            "forwarded": 0,
            "dropped": 0,
            "ttl_expired": 0,
            "source_invalid": 0,
            "no_route": 0,
            "total_processed": 0,
            "packet_types": {
                "ICMP": 0, "TCP": 0, "UDP": 0, "ARP": 0, "Other": 0
            }
        }
        self.update_statistics()
        self.update_graph()
        self.clear_logs()

    def clear_logs(self):
        self.log_text.delete(1.0, tk.END)

    def toggle_loss_sim(self):
        self.loss_simulation_on = not self.loss_simulation_on
        self.router.toggle_loss_simulation(self.loss_simulation_on)
        messagebox.showinfo("Loss Sim", f"Loss Simulation {'Enabled' if self.loss_simulation_on else 'Disabled'}")

    def export_packets(self):
        file = filedialog.asksaveasfilename(defaultextension=".pcap")
        if file:
            self.router.export_captured_packets(file)
            messagebox.showinfo("Export Success", f"Packets exported to:\n{file}")

    def show_network_map(self):
        """Show network map visualization"""
        try:
            # Check if networkx is installed
            import networkx
            import matplotlib
            from network_map import NetworkMap
            NetworkMap(self.root, self.router)
        except ImportError as e:
            messagebox.showwarning(
                "Missing Dependencies", 
                "Network map requires networkx and matplotlib packages.\n"
                "Install them with: pip install networkx matplotlib"
            )
            print(f"Error loading network map: {e}")

    def toggle_theme(self):
        if not self.dark_mode:
            self.root.configure(bg="#2e2e2e")
            self.main_frame.configure(style="Dark.TFrame")
            self.controls_frame.configure(style="Dark.TFrame")
            self.left_frame.configure(style="Dark.TFrame")
            self.right_frame.configure(style="Dark.TFrame")
            self.theme_status_label.config(text="Dark Mode Active")
            self.dark_mode = True
            self.fig.patch.set_facecolor('#2e2e2e')
        else:
            self.root.configure(bg="#f0f8ff")
            self.main_frame.configure(style="TFrame")
            self.controls_frame.configure(style="TFrame")
            self.left_frame.configure(style="TFrame")
            self.right_frame.configure(style="TFrame")
            self.theme_status_label.config(text="Light Mode Active")
            self.dark_mode = False
            self.fig.patch.set_facecolor('#ffffff')
        self.canvas.draw()

    def filter_routing_table(self, event=None):
        search = self.search_entry.get().lower()
        self.update_routing_table(search)

    def update_routing_table(self, search_filter=""):
        for item in self.routing_tree.get_children():
            self.routing_tree.delete(item)

        for route in self.router.routing_table["routes"]:
            values = (
                route.get("destination", ""),
                route.get("subnet", ""),
                route.get("next_hop", ""),
                route.get("interface", ""),
                route.get("priority", ""),
                route.get("cost", ""),
                route.get("last_used", "")
            )
            if search_filter:
                if not any(search_filter in str(v).lower() for v in values):
                    continue

            self.routing_tree.insert("", tk.END, values=values)
    def add_log_download(gui):
        """
        Add a simple log download button to the router GUI.
        Just call this function after creating your RouterGUI instance.
        
        Example usage in main.py:
            app = RouterGUI(root)
            add_log_download(app)
        """
        import tkinter as tk
        from tkinter import ttk, filedialog, messagebox
        import datetime
        
        # Define the download logs function
        def download_logs(self):
            """Download logs to a text file"""
            try:
                # Generate default filename with timestamp
                timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
                default_filename = f"router_logs_{timestamp}.txt"
                
                # Open file dialog
                file_path = filedialog.asksaveasfilename(
                    defaultextension=".txt",
                    filetypes=[("Text files", "*.txt"), ("Log files", "*.log"), ("All files", "*.*")],
                    title="Download Router Logs",
                    initialfile=default_filename
                )
                
                if not file_path:
                    return  # User cancelled
                    
                # Get logs
                logs = self.router.get_logs()
                
                # Write logs to file
                with open(file_path, 'w') as f:
                    # Write header
                    f.write(f"Virtual Router Logs - Downloaded on {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
                    f.write(f"Number of log entries: {len(logs)}\n")
                    f.write("-" * 80 + "\n\n")
                    
                    # Write all logs
                    for log in logs:
                        f.write(log + "\n")
                
                # Show success message
                messagebox.showinfo("Success", f"Logs downloaded to:\n{file_path}")
                
                # Add log entry about the download
                self.router.log_event(f"Logs downloaded to file: {file_path}", "INFO")
                
            except Exception as e:
                messagebox.showerror("Error", f"Failed to download logs: {str(e)}")
        
        # Add the method to the GUI class
        setattr(gui.__class__, 'download_logs', download_logs)
        
        # Create and add the download button
        try:
            # Find the logs panel
            if hasattr(gui, 'logs_frame'):
                # Create button
                download_button = ttk.Button(
                    gui.logs_frame, 
                    text="Download Logs", 
                    command=gui.download_logs
                )
                
                # Place it appropriately
                if hasattr(gui, 'log_text'):
                    # Add it above the text area
                    download_button.pack(side=tk.TOP, anchor=tk.W, padx=5, pady=5, before=gui.log_text)
                else:
                    # Just add it to the top of the frame
                    download_button.pack(side=tk.TOP, anchor=tk.W, padx=5, pady=5)
                    
                return True
        except Exception as e:
            print(f"Couldn't add log download button: {e}")
            return False

if __name__ == "__main__":
    root = tk.Tk()
    app = RouterGUI(root)
    root.mainloop()