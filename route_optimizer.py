# route_optimizer.py
import threading
import time
import random
import ipaddress
import socket
import copy
from datetime import datetime, timedelta
import tkinter as tk
from tkinter import ttk, messagebox

class RouteOptimizer:
    """Automatic route optimization and adjustment for the virtual router"""
    
    def __init__(self, router, refresh_callback=None):
        """Initialize the route optimizer
        
        Args:
            router: The VirtualRouter instance to optimize
            refresh_callback: Function to call to refresh the UI after route changes
        """
        self.router = router
        self.refresh_callback = refresh_callback
        self.running = False
        self.optimization_thread = None
        self.adjustment_interval = 10  # Seconds between adjustments
        self.optimization_mode = "normal"  # normal, aggressive, conservative
        
        # Statistics
        self.stats = {
            "routes_added": 0,
            "routes_deleted": 0,
            "priority_changes": 0,
            "last_adjustment": None
        }
        
        # Rules for automatic optimization
        self.rules = {
            "age_threshold": 600,  # Routes unused for 10 minutes get removed
            "priority_decay": 5,    # How much to increase priority per interval
            "max_routes": 50,       # Maximum number of routes
            "auto_add_enabled": True,  # Auto-add routes
            "auto_delete_enabled": True,  # Auto-delete routes
            "auto_priority_enabled": True  # Auto-adjust priorities
        }
    
    def start(self):
        """Start the route optimization process"""
        if self.running:
            return
            
        self.running = True
        self.optimization_thread = threading.Thread(target=self._optimization_loop, daemon=True)
        self.optimization_thread.start()
        
        if self.router:
            self.router.log_event("Route optimizer started", "INFO")
    
    def stop(self):
        """Stop the route optimization process"""
        self.running = False
        if self.optimization_thread:
            self.optimization_thread.join(timeout=2)
            self.optimization_thread = None
            
        if self.router:
            self.router.log_event("Route optimizer stopped", "INFO")
    
    def set_optimization_mode(self, mode):
        """Set the optimization mode
        
        Args:
            mode: One of 'normal', 'aggressive', 'conservative'
        """
        if mode not in ["normal", "aggressive", "conservative"]:
            return False
            
        self.optimization_mode = mode
        
        # Adjust rules based on mode
        if mode == "aggressive":
            self.rules["age_threshold"] = 300  # 5 minutes
            self.rules["priority_decay"] = 10
            self.adjustment_interval = 5  # Check every 5 seconds
        elif mode == "normal":
            self.rules["age_threshold"] = 600  # 10 minutes
            self.rules["priority_decay"] = 5
            self.adjustment_interval = 10  # Check every 10 seconds
        elif mode == "conservative":
            self.rules["age_threshold"] = 1800  # 30 minutes
            self.rules["priority_decay"] = 2
            self.adjustment_interval = 20  # Check every 20 seconds
            
        if self.router:
            self.router.log_event(f"Route optimizer mode set to {mode}", "INFO")
        return True
    
    def configure(self, **kwargs):
        """Configure the optimizer with new settings
        
        Args:
            **kwargs: Key-value pairs for configuration options
        """
        valid_keys = set(self.rules.keys()).union({"adjustment_interval"})
        
        for key, value in kwargs.items():
            if key in valid_keys:
                if key == "adjustment_interval":
                    self.adjustment_interval = value
                else:
                    self.rules[key] = value
        
        if self.router:
            self.router.log_event(f"Route optimizer configuration updated", "INFO")
    
    def _optimization_loop(self):
        """Main loop for automatic route optimization"""
        while self.running:
            try:
                self._adjust_routes()
                self.stats["last_adjustment"] = datetime.now()
                
                # Update UI if callback provided
                if self.refresh_callback:
                    self.refresh_callback()
                    
            except Exception as e:
                if self.router:
                    self.router.log_event(f"Route optimization error: {e}", "ERROR")
            
            # Sleep until next adjustment
            for _ in range(self.adjustment_interval):
                if not self.running:
                    break
                time.sleep(1)
    
    def _adjust_routes(self):
        """Perform route adjustments based on rules and current state"""
        if not self.router:
            return
            
        # Get a copy of the routing table
        routing_table = copy.deepcopy(self.router.routing_table)
        routes = routing_table.get("routes", [])
        
        # Track changes
        changes_made = False
        routes_deleted = 0
        routes_added = 0
        priorities_adjusted = 0
        
        # Phase 1: Adjust existing routes
        if self.rules["auto_delete_enabled"] or self.rules["auto_priority_enabled"]:
            # First pass - adjust priorities and mark routes for deletion
            routes_to_delete = []
            
            for i, route in enumerate(routes):
                # Skip default routes (0.0.0.0/0)
                if route.get("destination") == "0.0.0.0" and route.get("subnet") == "0":
                    continue
                
                # Check route age if it's been used
                if route.get("last_used"):
                    try:
                        last_used = datetime.strptime(route.get("last_used"), "%Y-%m-%d %H:%M:%S")
                        age_seconds = (datetime.now() - last_used).total_seconds()
                        
                        # Delete old routes
                        if self.rules["auto_delete_enabled"] and age_seconds > self.rules["age_threshold"]:
                            routes_to_delete.append((route.get("destination"), route.get("subnet")))
                            routes_deleted += 1
                            continue
                        
                        # Adjust priorities for aging routes
                        if self.rules["auto_priority_enabled"] and age_seconds > (self.rules["age_threshold"] / 2):
                            # Increase priority value (lower priority) for aging routes
                            route["priority"] = int(route.get("priority", 100)) + self.rules["priority_decay"]
                            priorities_adjusted += 1
                            changes_made = True
                    except Exception:
                        # Skip routes with invalid last_used
                        pass
            
            # Delete marked routes
            for dest, subnet in routes_to_delete:
                self.router.delete_route(dest, subnet)
                
            # Update statistics
            self.stats["routes_deleted"] += routes_deleted
        
        # Phase 2: Add new routes if enabled and below maximum
        if self.rules["auto_add_enabled"] and len(routes) < self.rules["max_routes"]:
            # Get existing destinations to avoid duplicates
            existing_destinations = {f"{r.get('destination')}/{r.get('subnet')}" 
                                    for r in self.router.routing_table.get("routes", [])}
            
            # Try to add a random route
            if random.random() < 0.3:  # 30% chance to add a route each cycle
                # Generate a random route
                new_route = self._generate_random_route(existing_destinations)
                
                if new_route:
                    success = self.router.add_route(
                        new_route["destination"],
                        new_route["subnet"],
                        new_route["next_hop"],
                        new_route["interface"],
                        new_route["priority"],
                        new_route["cost"]
                    )
                    
                    if success:
                        routes_added += 1
                        changes_made = True
        
        # Log summary of changes
        if routes_deleted > 0 or routes_added > 0 or priorities_adjusted > 0:
            self.router.log_event(
                f"Route optimization: {routes_added} added, {routes_deleted} deleted, "
                f"{priorities_adjusted} priorities adjusted", 
                "INFO"
            )
            
            # Update statistics
            self.stats["routes_added"] += routes_added
            self.stats["priority_changes"] += priorities_adjusted
    
    def _generate_random_route(self, existing_destinations):
        """Generate a realistic random route that doesn't conflict with existing ones
        
        Args:
            existing_destinations: Set of existing destination/subnet combinations
            
        Returns:
            dict: Route information or None if generation failed
        """
        # Get interfaces from the system
        try:
            import psutil
            interfaces = list(psutil.net_if_addrs().keys())
            if not interfaces:
                interfaces = ["eth0", "eth1", "wlan0"]
        except ImportError:
            interfaces = ["eth0", "eth1", "wlan0"]
        
        # Subnet options
        subnet_options = [16, 24, 28, 29, 30]
        
        # Try a few times to generate a non-conflicting route
        max_attempts = 10
        for _ in range(max_attempts):
            # Generate random IP address for destination network
            a = random.randint(1, 223)  # Avoid multicast, reserved, etc.
            b = random.randint(0, 255)
            c = random.randint(0, 255)
            d = 0  # Network address
            
            destination = f"{a}.{b}.{c}.{d}"
            
            # Pick a subnet mask
            subnet = random.choice(subnet_options)
            
            # Skip if this destination/subnet already exists
            if f"{destination}/{subnet}" in existing_destinations:
                continue
                
            # Generate a next hop in a related network
            next_hop = f"{a}.{b}.{c}.1"  # Gateway is typically .1
            
            # Pick a random interface
            interface = random.choice(interfaces)
            
            # Set reasonable priority and cost
            priority = random.randint(50, 200)
            cost = random.randint(1, 10)
            
            return {
                "destination": destination,
                "subnet": str(subnet),
                "next_hop": next_hop,
                "interface": interface,
                "priority": priority,
                "cost": cost
            }
        
        # Failed to generate a unique route
        return None
    
    def get_stats(self):
        """Get current optimizer statistics
        
        Returns:
            dict: Statistics about the optimizer
        """
        stats = copy.deepcopy(self.stats)
        
        # Format last adjustment time
        if stats["last_adjustment"]:
            stats["last_adjustment"] = stats["last_adjustment"].strftime("%Y-%m-%d %H:%M:%S")
            
        # Add current status
        stats["running"] = self.running
        stats["mode"] = self.optimization_mode
        
        return stats

    def show_config_dialog(self, parent):
        """Show configuration dialog for the route optimizer
        
        Args:
            parent: Parent window for the dialog
        """
        dialog = tk.Toplevel(parent)
        dialog.title("Route Optimizer Configuration")
        dialog.geometry("500x500")
        dialog.transient(parent)
        dialog.grab_set()
        
        # Create main frame
        main_frame = ttk.Frame(dialog, padding=10)
        main_frame.pack(fill=tk.BOTH, expand=True)
        
        # Status section
        status_frame = ttk.LabelFrame(main_frame, text="Optimizer Status", padding=10)
        status_frame.pack(fill=tk.X, padx=5, pady=5)
        
        status_text = f"Status: {'Running' if self.running else 'Stopped'}"
        ttk.Label(status_frame, text=status_text).grid(row=0, column=0, sticky=tk.W)
        
        # Start/Stop buttons
        btn_frame = ttk.Frame(status_frame)
        btn_frame.grid(row=0, column=1, padx=5)
        
        ttk.Button(btn_frame, text="Start", command=self.start).pack(side=tk.LEFT, padx=5)
        ttk.Button(btn_frame, text="Stop", command=self.stop).pack(side=tk.LEFT, padx=5)
        
        # Mode selection
        mode_frame = ttk.Frame(status_frame)
        mode_frame.grid(row=1, column=0, columnspan=2, sticky=tk.W, pady=5)
        
        ttk.Label(mode_frame, text="Optimization Mode:").pack(side=tk.LEFT, padx=5)
        mode_var = tk.StringVar(value=self.optimization_mode)
        mode_combo = ttk.Combobox(mode_frame, textvariable=mode_var, 
                                values=["conservative", "normal", "aggressive"],
                                width=15, state="readonly")
        mode_combo.pack(side=tk.LEFT, padx=5)
        
        def on_mode_change(event):
            self.set_optimization_mode(mode_var.get())
        
        mode_combo.bind("<<ComboboxSelected>>", on_mode_change)
        
        # Configuration section
        config_frame = ttk.LabelFrame(main_frame, text="Optimization Settings", padding=10)
        config_frame.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        # Create variables for settings
        check_vars = {}
        for option in ["auto_add_enabled", "auto_delete_enabled", "auto_priority_enabled"]:
            check_vars[option] = tk.BooleanVar(value=self.rules[option])
        
        slider_vars = {}
        slider_configs = {
            "age_threshold": {"from_": 60, "to": 3600, "label": "Age Threshold (seconds)"},
            "priority_decay": {"from_": 1, "to": 20, "label": "Priority Decay Rate"},
            "max_routes": {"from_": 10, "to": 100, "label": "Maximum Routes"},
            "adjustment_interval": {"from_": 5, "to": 60, "label": "Adjustment Interval (seconds)"}
        }
        
        for option, config in slider_configs.items():
            if option == "adjustment_interval":
                value = self.adjustment_interval
            else:
                value = self.rules[option]
            slider_vars[option] = tk.IntVar(value=value)
        
        # Create checkboxes
        check_frame = ttk.Frame(config_frame)
        check_frame.pack(fill=tk.X, pady=5)
        
        ttk.Checkbutton(check_frame, text="Auto-Add Routes", 
                       variable=check_vars["auto_add_enabled"]).pack(side=tk.LEFT, padx=10)
        ttk.Checkbutton(check_frame, text="Auto-Delete Routes", 
                       variable=check_vars["auto_delete_enabled"]).pack(side=tk.LEFT, padx=10)
        ttk.Checkbutton(check_frame, text="Auto-Adjust Priorities", 
                       variable=check_vars["auto_priority_enabled"]).pack(side=tk.LEFT, padx=10)
        
        # Create sliders
        slider_frame = ttk.Frame(config_frame)
        slider_frame.pack(fill=tk.BOTH, expand=True, pady=5)
        
        row = 0
        for option, config in slider_configs.items():
            ttk.Label(slider_frame, text=config["label"]).grid(row=row, column=0, sticky=tk.W, pady=5)
            slider = ttk.Scale(slider_frame, from_=config["from_"], to=config["to"], 
                              variable=slider_vars[option], orient=tk.HORIZONTAL, length=250)
            slider.grid(row=row, column=1, sticky=tk.W, padx=5)
            
            # Value display
            value_label = ttk.Label(slider_frame, text=str(slider_vars[option].get()))
            value_label.grid(row=row, column=2, padx=5)
            
            # Update value label when slider changes
            def make_update_func(label_widget, var):
                return lambda *args: label_widget.config(text=str(var.get()))
            
            slider.configure(command=make_update_func(value_label, slider_vars[option]))
            row += 1
        
        # Statistics section
        stats_frame = ttk.LabelFrame(main_frame, text="Statistics", padding=10)
        stats_frame.pack(fill=tk.X, padx=5, pady=5)
        
        stats = self.get_stats()
        stat_text = f"Routes Added: {stats['routes_added']}\n"
        stat_text += f"Routes Deleted: {stats['routes_deleted']}\n"
        stat_text += f"Priority Changes: {stats['priority_changes']}\n"
        stat_text += f"Last Adjustment: {stats['last_adjustment'] or 'Never'}"
        
        ttk.Label(stats_frame, text=stat_text, justify=tk.LEFT).pack(anchor=tk.W)
        
        # Buttons
        button_frame = ttk.Frame(main_frame)
        button_frame.pack(fill=tk.X, pady=10)
        
        def apply_settings():
            # Update settings
            for option, var in check_vars.items():
                self.rules[option] = var.get()
                
            for option, var in slider_vars.items():
                if option == "adjustment_interval":
                    self.adjustment_interval = var.get()
                else:
                    self.rules[option] = var.get()
            
            self.router.log_event("Route optimizer settings updated", "INFO")
            messagebox.showinfo("Success", "Optimizer settings have been updated")
        
        ttk.Button(button_frame, text="Apply Settings", command=apply_settings).pack(side=tk.LEFT, padx=5)
        ttk.Button(button_frame, text="Close", command=dialog.destroy).pack(side=tk.RIGHT, padx=5)

# Example usage in GUI
def integrate_with_gui(gui):
    """Integrate route optimizer with the router GUI
    
    Args:
        gui: The RouterGUI instance
    """
    # Create optimizer instance
    optimizer = RouteOptimizer(gui.router, gui.update_routing_table)
    gui.route_optimizer = optimizer
    
    # Add menu for optimizer
    menu_bar = tk.Menu(gui.root)
    gui.root.config(menu=menu_bar)
    
    tools_menu = tk.Menu(menu_bar, tearoff=0)
    menu_bar.add_cascade(label="Tools", menu=tools_menu)
    
    tools_menu.add_command(label="Route Optimizer", command=lambda: optimizer.show_config_dialog(gui.root))
    
    # Add buttons to GUI
    optimizer_frame = ttk.LabelFrame(gui.main_frame, text="Route Optimizer")
    optimizer_frame.pack(fill=tk.X, padx=10, pady=5, before=gui.controls_frame)
    
    btn_frame = ttk.Frame(optimizer_frame)
    btn_frame.pack(pady=5)
    
    ttk.Button(btn_frame, text="Start Optimizer", command=optimizer.start).pack(side=tk.LEFT, padx=5)
    ttk.Button(btn_frame, text="Stop Optimizer", command=optimizer.stop).pack(side=tk.LEFT, padx=5)
    ttk.Button(btn_frame, text="Configure", 
              command=lambda: optimizer.show_config_dialog(gui.root)).pack(side=tk.LEFT, padx=5)
    
    # Mode selection
    mode_frame = ttk.Frame(btn_frame)
    mode_frame.pack(side=tk.LEFT, padx=20)
    
    ttk.Label(mode_frame, text="Mode:").pack(side=tk.LEFT)
    mode_var = tk.StringVar(value="normal")
    mode_combo = ttk.Combobox(mode_frame, textvariable=mode_var, 
                            values=["conservative", "normal", "aggressive"],
                            width=12, state="readonly")
    mode_combo.pack(side=tk.LEFT, padx=5)
    
    def on_mode_change(event):
        optimizer.set_optimization_mode(mode_var.get())
    
    mode_combo.bind("<<ComboboxSelected>>", on_mode_change)
    
    # Status label
    status_var = tk.StringVar(value="Status: Not Running")
    status_label = ttk.Label(btn_frame, textvariable=status_var)
    status_label.pack(side=tk.LEFT, padx=20)
    
    # Update status periodically
    def update_status():
        stats = optimizer.get_stats()
        status = "Running" if stats["running"] else "Stopped"
        status_var.set(f"Status: {status} | Mode: {stats['mode'].title()} | Routes Added: {stats['routes_added']}")
        gui.root.after(2000, update_status)
    
    update_status()