# add_route_popup.py

import tkinter as tk
from tkinter import ttk, messagebox

class AddRoutePopup:
    def __init__(self, parent, router, refresh_callback):
        self.router = router
        self.refresh_callback = refresh_callback
        self.dialog = tk.Toplevel(parent)
        self.dialog.title("Add Route")
        self.dialog.geometry("400x400")
        self.dialog.transient(parent)
        self.dialog.grab_set()

        form = ttk.Frame(self.dialog, padding="10")
        form.pack(fill=tk.BOTH, expand=True)

        labels = ["Destination IP", "Subnet", "Next Hop", "Interface", "Priority", "Cost"]
        self.entries = {}
        for idx, label in enumerate(labels):
            ttk.Label(form, text=label + ":").grid(row=idx, column=0, sticky=tk.W, pady=5)
            entry = ttk.Entry(form)
            entry.grid(row=idx, column=1, padx=5, pady=5)
            self.entries[label] = entry

        # Interface dropdown
        import psutil
        interfaces = list(psutil.net_if_addrs().keys()) or ["eth0", "eth1"]
        self.entries["Interface"] = ttk.Combobox(form, values=interfaces)
        self.entries["Interface"].grid(row=3, column=1, padx=5, pady=5)
        if interfaces:
            self.entries["Interface"].set(interfaces[0])

        button_frame = ttk.Frame(form)
        button_frame.grid(row=len(labels), column=0, columnspan=2, pady=10)

        ttk.Button(button_frame, text="Save", command=self.save).pack(side=tk.LEFT, padx=5)
        ttk.Button(button_frame, text="Cancel", command=self.dialog.destroy).pack(side=tk.LEFT, padx=5)

    def save(self):
        try:
            destination = self.entries["Destination IP"].get().strip()
            subnet = self.entries["Subnet"].get().strip()
            next_hop = self.entries["Next Hop"].get().strip()
            interface = self.entries["Interface"].get().strip()
            priority = int(self.entries["Priority"].get().strip() or "100")
            cost = int(self.entries["Cost"].get().strip() or "1")

            if not destination or not subnet or not next_hop or not interface:
                messagebox.showerror("Error", "All fields are required")
                return

            success = self.router.add_route(destination, subnet, next_hop, interface, priority, cost)
            if success:
                self.refresh_callback()
                self.dialog.destroy()
            else:
                messagebox.showerror("Error", "Failed to add route")

        except Exception as e:
            messagebox.showerror("Error", f"Invalid input: {str(e)}")
