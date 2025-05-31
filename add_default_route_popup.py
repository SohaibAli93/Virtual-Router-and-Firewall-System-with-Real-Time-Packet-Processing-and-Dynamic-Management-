# add_default_route_popup.py

import tkinter as tk
from tkinter import ttk, messagebox

class AddDefaultRoutePopup:
    def __init__(self, parent, router, refresh_callback):
        self.router = router
        self.refresh_callback = refresh_callback
        self.dialog = tk.Toplevel(parent)
        self.dialog.title("Add Default Route (0.0.0.0/0)")
        self.dialog.geometry("400x350")
        self.dialog.transient(parent)
        self.dialog.grab_set()

        form = ttk.Frame(self.dialog, padding="10")
        form.pack(fill=tk.BOTH, expand=True)

        ttk.Label(form, text="Next Hop IP:").grid(row=0, column=0, sticky=tk.W, pady=5)
        self.next_hop_entry = ttk.Entry(form)
        self.next_hop_entry.grid(row=0, column=1, padx=5, pady=5)

        ttk.Label(form, text="Interface:").grid(row=1, column=0, sticky=tk.W, pady=5)
        import psutil
        interfaces = list(psutil.net_if_addrs().keys()) or ["eth0", "eth1"]
        self.interface_combo = ttk.Combobox(form, values=interfaces)
        self.interface_combo.grid(row=1, column=1, padx=5, pady=5)
        if interfaces:
            self.interface_combo.set(interfaces[0])

        ttk.Label(form, text="Priority (optional):").grid(row=2, column=0, sticky=tk.W, pady=5)
        self.priority_entry = ttk.Entry(form)
        self.priority_entry.grid(row=2, column=1, padx=5, pady=5)
        self.priority_entry.insert(0, "100")

        ttk.Label(form, text="Cost (optional):").grid(row=3, column=0, sticky=tk.W, pady=5)
        self.cost_entry = ttk.Entry(form)
        self.cost_entry.grid(row=3, column=1, padx=5, pady=5)
        self.cost_entry.insert(0, "1")

        button_frame = ttk.Frame(form)
        button_frame.grid(row=4, column=0, columnspan=2, pady=10)

        ttk.Button(button_frame, text="Save", command=self.save).pack(side=tk.LEFT, padx=5)
        ttk.Button(button_frame, text="Cancel", command=self.dialog.destroy).pack(side=tk.LEFT, padx=5)

    def save(self):
        try:
            next_hop = self.next_hop_entry.get().strip()
            interface = self.interface_combo.get().strip()
            priority = int(self.priority_entry.get().strip() or "100")
            cost = int(self.cost_entry.get().strip() or "1")

            if not next_hop or not interface:
                messagebox.showerror("Error", "Next hop and Interface are required")
                return

            success = self.router.add_route("0.0.0.0", "0", next_hop, interface, priority, cost)
            if success:
                self.refresh_callback()
                self.dialog.destroy()
            else:
                messagebox.showerror("Error", "Failed to add default route")

        except Exception as e:
            messagebox.showerror("Error", f"Invalid input: {str(e)}")
