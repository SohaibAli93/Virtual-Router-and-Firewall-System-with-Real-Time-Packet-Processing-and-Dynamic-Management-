# main.py with simple firewall integration
import tkinter as tk
from tkinter import ttk, filedialog, messagebox
from gui import RouterGUI
from gui_integration import integrate_route_optimizer
from datetime import datetime

# Log download function
def download_logs(router):
    try:
        # Generate default filename with timestamp
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
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
        logs = router.get_logs()
        
        # Write logs to file
        with open(file_path, 'w') as f:
            f.write(f"Virtual Router Logs - Downloaded on {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
            f.write(f"Number of log entries: {len(logs)}\n")
            f.write("-" * 80 + "\n\n")
            
            for log in logs:
                f.write(log + "\n")
        
        messagebox.showinfo("Success", f"Logs downloaded to:\n{file_path}")
        router.log_event(f"Logs downloaded to file: {file_path}", "INFO")
        
    except Exception as e:
        messagebox.showerror("Error", f"Failed to download logs: {str(e)}")

def add_log_download_button(app):
    if hasattr(app, 'logs_frame'):
        # Create button frame for logs
        button_frame = ttk.Frame(app.logs_frame)
        
        # Find text widget to put button above it
        for child in app.logs_frame.winfo_children():
            if isinstance(child, tk.Text):
                button_frame.pack(fill=tk.X, before=child, pady=2)
                break
        else:
            button_frame.pack(fill=tk.X, side=tk.TOP, pady=2)
        
        # Add download button
        ttk.Button(
            button_frame, 
            text="Download Logs", 
            command=lambda: download_logs(app.router)
        ).pack(side=tk.LEFT, padx=5)

def main():
    root = tk.Tk()
    app = RouterGUI(root)
    
    # Initialize route optimizer
    optimizer = integrate_route_optimizer(app, app.router)
    
    # Initialize simple firewall
    
    # Add log download button
    add_log_download_button(app)
    
    root.mainloop()

if __name__ == "__main__":
    main()