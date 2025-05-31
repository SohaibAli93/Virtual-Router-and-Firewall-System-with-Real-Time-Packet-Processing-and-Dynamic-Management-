# network_map.py
import tkinter as tk
from tkinter import ttk, messagebox, filedialog
import networkx as nx
import matplotlib.pyplot as plt
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg
import matplotlib.colors as mcolors
import ipaddress
import random
from matplotlib.figure import Figure

class NetworkMap:
    def __init__(self, parent, router):
        """Initialize the network map with router instance"""
        self.parent = parent
        self.router = router
        self.tooltip = None
        self.last_hover_node = None
        self.create_window()
        
    def create_window(self):
        """Create the network map window"""
        self.window = tk.Toplevel(self.parent)
        self.window.title("Network Map Visualization")
        self.window.geometry("900x700")
        self.window.minsize(800, 600)
        self.window.transient(self.parent)
        
        # Create main frame with padding
        main_frame = ttk.Frame(self.window, padding=10)
        main_frame.pack(fill=tk.BOTH, expand=True)
        
        # Create top area with help text
        help_frame = ttk.LabelFrame(main_frame, text="Network Map Help", padding=5)
        help_frame.pack(fill=tk.X, pady=(0, 10))
        
        help_text = """
        This map visualizes your routing table. Choose a view type from the dropdown menu:
        • Subnet View: Shows subnets (blue) and next hops (orange)
        • Router View: Focuses on routers and their connections
        • Interface View: Shows network interfaces and their relationships
        • Priority View: Groups routes by priority level
        
        Hover over nodes for details. Adjust display settings below.
        """
        ttk.Label(help_frame, text=help_text, wraplength=800, justify=tk.LEFT).pack(fill=tk.X)
        
        # Create controls frame with better organization
        control_frame = ttk.Frame(main_frame)
        control_frame.pack(fill=tk.X, pady=(0, 5))
        
        # Left controls
        left_controls = ttk.Frame(control_frame)
        left_controls.pack(side=tk.LEFT, fill=tk.Y)
        
        ttk.Label(left_controls, text="Map Type:").pack(side=tk.LEFT, padx=5)
        self.map_type = tk.StringVar(value="subnet")
        map_options = ["subnet", "router", "interface", "priority"]
        self.map_combo = ttk.Combobox(left_controls, textvariable=self.map_type, values=map_options, width=10)
        self.map_combo.pack(side=tk.LEFT, padx=5)
        self.map_combo.bind("<<ComboboxSelected>>", self.refresh_map)
        
        # Right controls
        right_controls = ttk.Frame(control_frame)
        right_controls.pack(side=tk.RIGHT, fill=tk.Y)
        
        ttk.Button(right_controls, text="Refresh Map", command=self.refresh_map).pack(side=tk.LEFT, padx=5)
        ttk.Button(right_controls, text="Save Image", command=self.save_image).pack(side=tk.LEFT, padx=5)
        ttk.Button(right_controls, text="Legend", command=self.show_legend).pack(side=tk.LEFT, padx=5)
        
        # Add options frame with better layout
        options_frame = ttk.LabelFrame(main_frame, text="Display Options", padding=5)
        options_frame.pack(fill=tk.X, pady=(0, 10))
        
        # Create a grid layout for options
        options_grid = ttk.Frame(options_frame)
        options_grid.pack(fill=tk.X, padx=10, pady=5)
        
        # First row
        ttk.Label(options_grid, text="Node Size:").grid(row=0, column=0, sticky=tk.W, padx=5)
        self.node_size_var = tk.IntVar(value=800)
        node_size_scale = ttk.Scale(options_grid, from_=200, to=2000, 
                                   variable=self.node_size_var, orient=tk.HORIZONTAL, length=150)
        node_size_scale.grid(row=0, column=1, padx=5, pady=5)
        node_size_scale.bind("<ButtonRelease-1>", self.refresh_map)
        
        ttk.Label(options_grid, text="Font Size:").grid(row=0, column=2, sticky=tk.W, padx=5)
        self.font_size_var = tk.IntVar(value=10)
        font_size_scale = ttk.Scale(options_grid, from_=6, to=16, 
                                  variable=self.font_size_var, orient=tk.HORIZONTAL, length=150)
        font_size_scale.grid(row=0, column=3, padx=5, pady=5)
        font_size_scale.bind("<ButtonRelease-1>", self.refresh_map)
        
        # Second row
        ttk.Label(options_grid, text="Edge Width:").grid(row=1, column=0, sticky=tk.W, padx=5)
        self.edge_width_var = tk.DoubleVar(value=1.5)
        edge_width_scale = ttk.Scale(options_grid, from_=0.5, to=3.0, 
                                    variable=self.edge_width_var, orient=tk.HORIZONTAL, length=150)
        edge_width_scale.grid(row=1, column=1, padx=5, pady=5)
        edge_width_scale.bind("<ButtonRelease-1>", self.refresh_map)
        
        # Checkboxes
        checkbox_frame = ttk.Frame(options_grid)
        checkbox_frame.grid(row=1, column=2, columnspan=2, sticky=tk.W)
        
        self.show_costs_var = tk.BooleanVar(value=True)
        costs_check = ttk.Checkbutton(checkbox_frame, text="Show Costs", variable=self.show_costs_var)
        costs_check.pack(side=tk.LEFT, padx=10)
        costs_check.bind("<ButtonRelease-1>", lambda e: self.window.after(100, self.refresh_map))
        
        self.show_priorities_var = tk.BooleanVar(value=True)
        priorities_check = ttk.Checkbutton(checkbox_frame, text="Show Priorities", variable=self.show_priorities_var)
        priorities_check.pack(side=tk.LEFT, padx=10)
        priorities_check.bind("<ButtonRelease-1>", lambda e: self.window.after(100, self.refresh_map))
        
        self.show_labels_var = tk.BooleanVar(value=True)
        labels_check = ttk.Checkbutton(checkbox_frame, text="Show Labels", variable=self.show_labels_var)
        labels_check.pack(side=tk.LEFT, padx=10)
        labels_check.bind("<ButtonRelease-1>", lambda e: self.window.after(100, self.refresh_map))
        
        # Create a frame for the map with border
        map_container = ttk.LabelFrame(main_frame, text="Network Topology Map")
        map_container.pack(fill=tk.BOTH, expand=True)
        
        self.map_frame = ttk.Frame(map_container, padding=5)
        self.map_frame.pack(fill=tk.BOTH, expand=True)
        
        # Status bar for node info
        self.status_frame = ttk.Frame(main_frame, relief=tk.SUNKEN, padding=2)
        self.status_frame.pack(fill=tk.X, side=tk.BOTTOM, pady=(5, 0))
        self.status_label = ttk.Label(self.status_frame, text="Ready. Hover over a node to see details.")
        self.status_label.pack(anchor=tk.W)
        
        # Make window resizable and create map
        self.window.bind("<Configure>", self.on_window_resize)
        self.last_window_size = (self.window.winfo_width(), self.window.winfo_height())
        self.create_map()
    
    def on_window_resize(self, event):
        """Handle window resize events"""
        # Only refresh if the size changed significantly to avoid constant redraws
        current_size = (self.window.winfo_width(), self.window.winfo_height())
        w_diff = abs(current_size[0] - self.last_window_size[0])
        h_diff = abs(current_size[1] - self.last_window_size[1])
        
        if w_diff > 50 or h_diff > 50:  # Only redraw on significant changes
            self.last_window_size = current_size
            self.window.after(100, self.create_map)  # Small delay to batch resize events
        
    def create_map(self):
        """Create the network map using networkx and matplotlib"""
        # Clear the frame
        for widget in self.map_frame.winfo_children():
            widget.destroy()
            
        # Create figure and axes - make it responsive to window size
        width_inches = self.window.winfo_width() / 100
        height_inches = self.window.winfo_height() / 100
        
        self.fig = Figure(figsize=(width_inches, height_inches), tight_layout=True)
        self.ax = self.fig.add_subplot(111)
        self.ax.clear()
        
        # Create graph based on router info
        map_type = self.map_type.get()
        G = self.build_graph(map_type)
        
        # Get layout
        if len(G.nodes()) > 0:
            try:
                if map_type == "subnet":
                    layout = nx.spring_layout(G, seed=42, k=0.3)
                elif map_type == "router":
                    layout = nx.kamada_kawai_layout(G)
                elif map_type == "interface":
                    layout = nx.spring_layout(G, seed=42, k=0.5)
                else:
                    layout = nx.shell_layout(G)
            except:
                # Fallback if layout algorithm fails
                layout = nx.spring_layout(G, seed=42)
                
            # Store the layout for tooltip positioning
            self.current_layout = layout
            self.current_graph = G
                
            # Draw the graph
            node_size = self.node_size_var.get()
            font_size = self.font_size_var.get()
            edge_width = self.edge_width_var.get()
            
            # Node colors based on map type
            node_colors = self.get_node_colors(G, map_type)
            
            # Draw nodes
            nx.draw_networkx_nodes(G, layout, node_size=node_size, node_color=node_colors, 
                                 alpha=0.8, ax=self.ax, edgecolors='black', linewidths=1)
            
            # Draw edges
            edge_labels = {}
            for u, v, data in G.edges(data=True):
                label = ""
                if self.show_costs_var.get() and 'cost' in data:
                    label += f"C:{data['cost']} "
                if self.show_priorities_var.get() and 'priority' in data:
                    label += f"P:{data['priority']}"
                if label:
                    edge_labels[(u, v)] = label
                    
            nx.draw_networkx_edges(G, layout, width=edge_width, alpha=0.7, 
                                  arrows=True, arrowsize=15, ax=self.ax, 
                                  connectionstyle='arc3,rad=0.1')
                                  
            # Draw edge labels if we have any
            if edge_labels and (self.show_costs_var.get() or self.show_priorities_var.get()):
                nx.draw_networkx_edge_labels(G, layout, edge_labels=edge_labels, 
                                          font_size=font_size-2, ax=self.ax)
            
            # Draw labels if enabled
            if self.show_labels_var.get():
                nx.draw_networkx_labels(G, layout, font_size=font_size, ax=self.ax)
            
            self.ax.set_title(f"Network Map - {map_type.title()} View", fontsize=14)
            self.ax.axis('off')
            
            # Create canvas
            self.canvas = FigureCanvasTkAgg(self.fig, master=self.map_frame)
            self.canvas.draw()
            canvas_widget = self.canvas.get_tk_widget()
            canvas_widget.pack(fill=tk.BOTH, expand=True)
            
            # Set up mouse events for tooltips
            canvas_widget.bind("<Motion>", self.on_mouse_move)
            canvas_widget.bind("<Leave>", self.on_mouse_leave)
            
        else:
            # No routes
            self.ax.text(0.5, 0.5, "No routes available in the routing table.\nAdd routes to see the network map.", 
                     ha='center', va='center', fontsize=14, multialignment='center')
            self.ax.axis('off')
            
            # Create canvas
            canvas = FigureCanvasTkAgg(self.fig, master=self.map_frame)
            canvas.draw()
            canvas.get_tk_widget().pack(fill=tk.BOTH, expand=True)
    
    def build_graph(self, map_type):
        """Build a networkx graph based on the routing table"""
        G = nx.DiGraph()
        
        # Get routes from router
        routes = self.router.routing_table.get("routes", [])
        
        if map_type == "subnet":
            # Subnet-based view
            for route in routes:
                dest = route.get("destination")
                subnet = route.get("subnet", "24")
                next_hop = route.get("next_hop")
                interface = route.get("interface")
                cost = route.get("cost", 1)
                priority = route.get("priority", 100)
                
                # Skip default routes for better visualization
                if dest == "0.0.0.0":
                    continue
                    
                # Create subnet representation
                subnet_name = f"{dest}/{subnet}"
                
                # Add nodes with attributes
                if subnet_name not in G:
                    G.add_node(subnet_name, type="subnet", 
                              tooltip=f"Subnet: {subnet_name}\nReached via: {next_hop}")
                if next_hop not in G:
                    G.add_node(next_hop, type="router", 
                              tooltip=f"Router: {next_hop}\nInterface: {interface}")
                    
                # Add edge with attributes
                G.add_edge(subnet_name, next_hop, cost=cost, priority=priority,
                          tooltip=f"Route: {subnet_name} → {next_hop}\nCost: {cost}, Priority: {priority}")
                
        elif map_type == "router":
            # Router-based view (next-hop perspective)
            routers = set()
            for route in routes:
                next_hop = route.get("next_hop")
                routers.add(next_hop)
                
            # Add all routers as nodes
            for router in routers:
                G.add_node(router, type="router", 
                         tooltip=f"Router: {router}")
                
            # Add connections between routers
            for route in routes:
                dest = route.get("destination")
                if dest == "0.0.0.0":
                    continue  # Skip default routes
                    
                next_hop = route.get("next_hop")
                cost = route.get("cost", 1)
                priority = route.get("priority", 100)
                
                # Try to find a router that matches the destination
                matching_router = None
                for router in routers:
                    try:
                        # Check if destination is in the same network as router
                        if ipaddress.ip_address(dest) == ipaddress.ip_address(router):
                            matching_router = router
                            break
                    except:
                        pass
                        
                if matching_router and matching_router != next_hop:
                    G.add_edge(next_hop, matching_router, cost=cost, priority=priority,
                              tooltip=f"Link: {next_hop} → {matching_router}\nCost: {cost}, Priority: {priority}")
                    
        elif map_type == "interface":
            # Interface-based view
            interfaces = set()
            interface_ips = {}  # Map interfaces to their IPs
            
            for route in routes:
                interface = route.get("interface")
                next_hop = route.get("next_hop")
                interfaces.add(interface)
                
                # Associate interface with IPs
                if interface not in interface_ips:
                    interface_ips[interface] = []
                if next_hop not in interface_ips[interface]:
                    interface_ips[interface].append(next_hop)
                
            # Add all interfaces as nodes
            for interface in interfaces:
                ips = interface_ips.get(interface, [])
                ip_text = ", ".join(ips[:3])
                if len(ips) > 3:
                    ip_text += f" and {len(ips)-3} more"
                    
                G.add_node(interface, type="interface", 
                         tooltip=f"Interface: {interface}\nAssociated IPs: {ip_text}")
                
            # Add connections between interfaces via next-hops
            next_hops = {}
            for route in routes:
                interface = route.get("interface")
                next_hop = route.get("next_hop")
                if next_hop not in next_hops:
                    next_hops[next_hop] = []
                if interface not in next_hops[next_hop]:
                    next_hops[next_hop].append(interface)
                
            # Connect interfaces that share a next-hop
            for next_hop, connected_interfaces in next_hops.items():
                for i in range(len(connected_interfaces)):
                    for j in range(i+1, len(connected_interfaces)):
                        if connected_interfaces[i] != connected_interfaces[j]:
                            G.add_edge(connected_interfaces[i], connected_interfaces[j], 
                                     next_hop=next_hop, weight=1,
                                     tooltip=f"Interfaces connected via {next_hop}")
                            G.add_edge(connected_interfaces[j], connected_interfaces[i], 
                                     next_hop=next_hop, weight=1,
                                     tooltip=f"Interfaces connected via {next_hop}")
                        
        elif map_type == "priority":
            # Priority-based view
            priorities = set()
            
            # First collect all unique priorities
            for route in routes:
                priority = route.get("priority", 100)
                priorities.add(priority)
                
            # Add priority nodes
            for priority in sorted(priorities):
                priority_group = f"P{priority}"
                G.add_node(priority_group, type="priority", 
                         tooltip=f"Priority Level: {priority}\n(Lower number = Higher priority)")
            
            # Add subnet nodes and connect to priorities
            for route in routes:
                dest = route.get("destination")
                subnet = route.get("subnet", "24")
                next_hop = route.get("next_hop")
                cost = route.get("cost", 1)
                priority = route.get("priority", 100)
                
                # Skip default routes for better visualization
                if dest == "0.0.0.0":
                    continue
                    
                # Create priority grouping
                priority_group = f"P{priority}"
                subnet_name = f"{dest}/{subnet}"
                
                # Add subnet node
                if subnet_name not in G:
                    G.add_node(subnet_name, type="subnet",
                              tooltip=f"Subnet: {subnet_name}\nNext hop: {next_hop}\nCost: {cost}")
                    
                # Add edge with attributes
                G.add_edge(priority_group, subnet_name, cost=cost, next_hop=next_hop,
                         tooltip=f"Route with priority {priority} to {subnet_name}\nvia {next_hop}")
                
        return G
        
    def get_node_colors(self, G, map_type):
        """Generate node colors based on the map type"""
        colors = []
        
        if map_type == "subnet":
            for node in G.nodes():
                if '/' in str(node):  # This is a subnet
                    colors.append('#72a0c1')  # Blue for subnets
                else:  # This is a next hop
                    colors.append('#ff7f50')  # Orange for next hops
        
        elif map_type == "router":
            # Use color gradient for routers based on number of connections
            degrees = dict(G.degree())
            max_degree = max(degrees.values()) if degrees else 1
            
            for node in G.nodes():
                # Color based on number of connections (degree)
                degree = degrees.get(node, 0)
                # Use a color gradient from light orange to dark orange
                intensity = 0.3 + 0.7 * (degree / max_degree) if max_degree > 0 else 0.5
                colors.append(mcolors.to_rgba('orangered', intensity))
            
        elif map_type == "interface":
            # Generate colors based on interface types
            for node in G.nodes():
                node_str = str(node).lower()
                if 'eth' in node_str:
                    colors.append('#72a0c1')  # Blue for Ethernet
                elif 'wlan' in node_str or 'wifi' in node_str:
                    colors.append('#90ee90')  # Green for wireless
                elif 'lo' in node_str:
                    colors.append('#d3d3d3')  # Gray for loopback
                else:
                    colors.append('#ffb6c1')  # Pink for other
                    
        elif map_type == "priority":
            # Generate colors based on priority values
            for node in G.nodes():
                if str(node).startswith('P'):
                    # Extract priority number
                    try:
                        priority = int(str(node)[1:])
                        # Higher priority (lower number) gets more intense color
                        intensity = max(0, min(255, 255 - (priority * 2)))
                        colors.append(f'#{intensity:02x}80{255-intensity:02x}')
                    except:
                        colors.append('#a0a0a0')  # Gray for invalid priority
                else:
                    colors.append('#72a0c1')  # Blue for subnets
        
        return colors
    
    def on_mouse_move(self, event):
        """Handle mouse movement to show tooltips"""
        if not hasattr(self, 'current_layout') or not hasattr(self, 'current_graph'):
            return
            
        # Convert mouse position to figure coordinates
        x, y = event.x, event.y
        try:
            # Convert display coordinates to data coordinates
            ax_x, ax_y = self.ax.transData.inverted().transform([x, y])
            
            # Find closest node
            min_dist = float('inf')
            closest_node = None
            
            for node, pos in self.current_layout.items():
                node_x, node_y = pos
                dist = ((node_x - ax_x) ** 2 + (node_y - ax_y) ** 2) ** 0.5
                if dist < min_dist:
                    min_dist = dist
                    closest_node = node
            
            # Check if mouse is close enough to node (adjust threshold as needed)
            node_size = self.node_size_var.get()
            threshold = node_size / 10000  # Adjust based on node size
            
            if min_dist < threshold and closest_node is not None:
                # Get node data
                node_data = self.current_graph.nodes[closest_node]
                tooltip_text = node_data.get('tooltip', str(closest_node))
                
                # Update status bar
                self.status_label.config(text=tooltip_text.replace('\n', ' | '))
                
                # Show tooltip if node changed
                if self.last_hover_node != closest_node:
                    self.hide_tooltip()
                    self.show_tooltip(event, tooltip_text)
                    self.last_hover_node = closest_node
                return
                
            # Not near any node
            if self.last_hover_node is not None:
                self.status_label.config(text="Ready. Hover over a node to see details.")
                self.hide_tooltip()
                self.last_hover_node = None
                
        except Exception as e:
            print(f"Tooltip error: {e}")
    
    def on_mouse_leave(self, event):
        """Handle mouse leaving the canvas"""
        self.hide_tooltip()
        self.status_label.config(text="Ready. Hover over a node to see details.")
        self.last_hover_node = None
        
    def show_tooltip(self, event, text):
        """Show tooltip at mouse position"""
        x, y = event.x, event.y
        
        # Destroy existing tooltip if any
        self.hide_tooltip()
        
        # Create new tooltip
        self.tooltip = tk.Toplevel(self.window)
        self.tooltip.wm_overrideredirect(True)  # No window border
        
        # Position tooltip near cursor but ensure it's visible
        x_pos = self.window.winfo_rootx() + event.x + 15
        y_pos = self.window.winfo_rooty() + event.y + 10
        
        self.tooltip.wm_geometry(f"+{x_pos}+{y_pos}")
        
        # Create tooltip content
        tip_frame = ttk.Frame(self.tooltip, relief=tk.SOLID, borderwidth=1)
        tip_frame.pack(fill=tk.BOTH, expand=True)
        
        label = ttk.Label(tip_frame, text=text, justify=tk.LEFT, 
                         background="#FFFFAA", padding=5)
        label.pack()
        
    def hide_tooltip(self):
        """Hide the current tooltip if it exists"""
        if self.tooltip:
            self.tooltip.destroy()
            self.tooltip = None
            
    def show_legend(self):
        """Show a legend window"""
        legend_window = tk.Toplevel(self.window)
        legend_window.title("Network Map Legend")
        legend_window.geometry("400x450")
        legend_window.transient(self.window)
        
        frame = ttk.Frame(legend_window, padding=10)
        frame.pack(fill=tk.BOTH, expand=True)
        
        # Title
        ttk.Label(frame, text="Network Map Legend", font=("Arial", 14, "bold")).pack(pady=(0, 10))
        
        # Create legend content based on current map type
        map_type = self.map_type.get()
        
        if map_type == "subnet":
            legend_text = """
            Subnet View Legend:
            
            • Blue Nodes: Subnets (e.g. 192.168.1.0/24)
            • Orange Nodes: Next Hops/Routers
            • Arrows: Direction of routing from subnet to next hop
            • C: Cost of the route
            • P: Priority of the route (lower = higher priority)
            
            This view shows how subnets connect to routers.
            """
        elif map_type == "router":
            legend_text = """
            Router View Legend:
            
            • Orange Nodes: Routers (next hops)
            • Node Brightness: Based on number of connections
            • Arrows: Traffic flow between routers
            • C: Cost of the route
            • P: Priority of the route (lower = higher priority)
            
            This view focuses on router-to-router relationships.
            """
        elif map_type == "interface":
            legend_text = """
            Interface View Legend:
            
            • Blue Nodes: Ethernet interfaces
            • Green Nodes: Wireless interfaces
            • Gray Nodes: Loopback interfaces
            • Pink Nodes: Other interface types
            • Connections: Interfaces that share next hops
            
            This view shows which network interfaces are related.
            """
        elif map_type == "priority":
            legend_text = """
            Priority View Legend:
            
            • Color Gradient Nodes: Priority levels (P100, P200, etc.)
            • Blue Nodes: Subnets
            • Brighter Color: Higher priority (lower number)
            • Connections: Routes from priority level to subnet
            
            This view groups routes by priority level.
            """
        
        # Add common instructions
        common_text = """
        Interactive Features:
        
        • Hover over any node to see detailed information
        • Adjust node size and font size using the sliders
        • Toggle costs, priorities, and labels using checkboxes
        • Save the current view as a high-resolution image
        • The status bar at the bottom shows node details
        
        The map automatically adjusts when you resize the window.
        """
        
        # Show the legend text
        legend_label = ttk.Label(frame, text=legend_text + common_text, 
                               justify=tk.LEFT, wraplength=380)
        legend_label.pack(fill=tk.BOTH, expand=True)
        
        # Close button
        ttk.Button(frame, text="Close", command=legend_window.destroy).pack(pady=10)
        
    def refresh_map(self, event=None):
        """Refresh the network map"""
        self.create_map()
        
    def save_image(self):
        """Save the network map as an image"""
        try:
            file_path = filedialog.asksaveasfilename(
                defaultextension=".png",
                filetypes=[("PNG files", "*.png"), 
                          ("JPEG files", "*.jpg"), 
                          ("PDF files", "*.pdf"),
                          ("SVG files", "*.svg"),
                          ("All files", "*.*")]
            )
            if file_path:
                # Save with high resolution
                self.fig.savefig(file_path, bbox_inches='tight', dpi=300)
                messagebox.showinfo("Success", f"Map saved to {file_path}")
        except Exception as e:
            messagebox.showerror("Error", f"Failed to save image: {str(e)}")