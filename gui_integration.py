# gui_integration.py
"""
This file contains code to integrate the RouteOptimizer into the existing GUI.
To use this, import the necessary functions into your main.py file.
"""

import tkinter as tk
from tkinter import ttk

def integrate_route_optimizer(gui, router):
    """
    Integrate the route optimizer into the existing GUI
    
    This function should be called after the GUI has been initialized.
    """
    try:
        from route_optimizer import RouteOptimizer
        
        # Create an instance of the route optimizer
        optimizer = RouteOptimizer(router, gui.update_routing_table)
        gui.route_optimizer = optimizer
        
        # Add the optimizer panel to the GUI
        add_optimizer_panel(gui, optimizer)
        
        return optimizer
    except ImportError as e:
        print(f"Error importing RouteOptimizer: {e}")
        return None
        
def add_optimizer_panel(gui, optimizer):
    """Add the route optimizer panel to the GUI"""
    
    # Create a new frame at the top of the GUI
    optimizer_frame = ttk.LabelFrame(gui.main_frame, text="Automatic Route Management")
    
    # Insert the optimizer frame before the controls frame
    # We need to move existing widgets to make room
    children = gui.main_frame.winfo_children()
    
    # Find position of controls_frame to insert before it
    try:
        controls_index = children.index(gui.controls_frame)
    except ValueError:
        # If controls_frame is not found, insert at the beginning
        controls_index = 0
    
    optimizer_frame.pack(fill=tk.X, padx=10, pady=5)
    
    # Reorder widgets to put optimizer_frame before controls_frame
    optimizer_frame.pack_forget()
    if hasattr(gui, 'controls_frame'):
        optimizer_frame.pack(fill=tk.X, padx=10, pady=5, before=gui.controls_frame)
    else:
        optimizer_frame.pack(fill=tk.X, padx=10, pady=5)
    
    # Create the optimizer controls
    button_frame = ttk.Frame(optimizer_frame)
    button_frame.pack(fill=tk.X, pady=5)
    
    ttk.Label(button_frame, text="Route Management:").pack(side=tk.LEFT, padx=5)
    
    # Start/Stop buttons
    ttk.Button(button_frame, text="Start", command=optimizer.start, 
              width=8).pack(side=tk.LEFT, padx=3)
    ttk.Button(button_frame, text="Stop", command=optimizer.stop, 
              width=8).pack(side=tk.LEFT, padx=3)
    
    # Configure button
    ttk.Button(button_frame, text="Configure", 
              command=lambda: optimizer.show_config_dialog(gui.root), 
              width=10).pack(side=tk.LEFT, padx=3)
    
    # Mode selection
    mode_frame = ttk.Frame(button_frame)
    mode_frame.pack(side=tk.LEFT, padx=10)
    
    ttk.Label(mode_frame, text="Mode:").pack(side=tk.LEFT, padx=2)
    
    mode_var = tk.StringVar(value="normal")
    mode_combo = ttk.Combobox(mode_frame, textvariable=mode_var, 
                            values=["conservative", "normal", "aggressive"],
                            width=12, state="readonly")
    mode_combo.pack(side=tk.LEFT, padx=3)
    
    # Update optimizer mode when selection changes
    def on_mode_change(event):
        optimizer.set_optimization_mode(mode_var.get())
    
    mode_combo.bind("<<ComboboxSelected>>", on_mode_change)
    
    # Status indicator
    status_var = tk.StringVar(value="Status: Not Running")
    status_label = ttk.Label(button_frame, textvariable=status_var)
    status_label.pack(side=tk.RIGHT, padx=10)
    
    # Update the status periodically
    def update_status():
        """Update the status display with current optimizer information"""
        stats = optimizer.get_stats()
        status = "Running" if stats["running"] else "Stopped"
        mode = stats["mode"].title()
        
        status_text = f"Status: {status} | Mode: {mode}"
        if stats["running"]:
            status_text += f" | Added: {stats['routes_added']} | Deleted: {stats['routes_deleted']}"
            
        status_var.set(status_text)
        gui.root.after(2000, update_status)
    
    # Start the status updates
    update_status()

def update_main_py(file_path="main.py"):
    """
    Function to update main.py to integrate the route optimizer
    
    This is a helper function for instructional purposes.
    """
    integration_code = """
# Import the route optimizer integration
from gui_integration import integrate_route_optimizer

def main():
    root = tk.Tk()
    app = RouterGUI(root)
    
    # Initialize the route optimizer
    optimizer = integrate_route_optimizer(app, app.router)
    
    root.mainloop()

if __name__ == "__main__":
    main()
"""
    
    print("To update your main.py, add the following code:")
    print(integration_code)
    
    # Note: This function doesn't actually modify the file
    # It just shows what code to add