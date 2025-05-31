# firewall_manager_popup.py

import tkinter as tk
from tkinter import ttk, messagebox, filedialog
import json

class FirewallManagerPopup:
    def __init__(self, parent, firewall, refresh_callback=None):
        self.parent = parent
        self.firewall = firewall
        self.refresh_callback = refresh_callback

        self.window = tk.Toplevel(parent)
        self.window.title("Firewall Rules Manager")
        self.window.geometry("1100x650")
        self.window.transient(parent)
        self.window.grab_set()

        self.setup_ui()
        self.load_rules()

        self.window.after(3000, self.refresh_hit_counts)  # Auto-refresh hit counts

    def setup_ui(self):
        # Top Button + Search Bar
        button_frame = ttk.Frame(self.window)
        button_frame.pack(fill=tk.X, pady=5)

        ttk.Button(button_frame, text="Add Rule", command=self.add_rule_popup).pack(side=tk.LEFT, padx=5)
        ttk.Button(button_frame, text="Delete Rule", command=self.delete_rule).pack(side=tk.LEFT, padx=5)
        ttk.Button(button_frame, text="Enable/Disable", command=self.toggle_rule).pack(side=tk.LEFT, padx=5)
        ttk.Button(button_frame, text="Export Rules", command=self.export_rules).pack(side=tk.LEFT, padx=5)
        ttk.Button(button_frame, text="Import Rules", command=self.import_rules).pack(side=tk.LEFT, padx=5)

        # Search Bar
        ttk.Label(button_frame, text="Search:").pack(side=tk.LEFT, padx=10)
        self.search_var = tk.StringVar()
        self.search_var.trace_add("write", lambda *args: self.load_rules())
        search_entry = ttk.Entry(button_frame, textvariable=self.search_var)
        search_entry.pack(side=tk.LEFT, padx=5)

        # Firewall Rules Table
        self.columns = ("Rule ID", "Action", "Source IP", "Destination IP", "Protocol", "Source Port", "Dest Port", "Hits", "Enabled", "Description")
        self.tree = ttk.Treeview(self.window, columns=self.columns, show="headings")
        for col in self.columns:
            self.tree.heading(col, text=col)
            self.tree.column(col, width=100)
        self.tree.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)

        scrollbar_y = ttk.Scrollbar(self.tree, orient=tk.VERTICAL, command=self.tree.yview)
        self.tree.configure(yscroll=scrollbar_y.set)
        scrollbar_y.pack(side=tk.RIGHT, fill=tk.Y)

        self.setup_row_styles()

    def setup_row_styles(self):
        style = ttk.Style()
        style.map('Treeview', background=[('selected', 'blue')])
        style.configure('AllowRow.Treeview', background='#d4f4dd')   # Light green for allow
        style.configure('BlockRow.Treeview', background='#f4d4d4')   # Light red for block
        style.configure('DisabledRow.Treeview', background='#e0e0e0')  # Grey for disabled

    def load_rules(self):
        # Clear current entries
        for row in self.tree.get_children():
            self.tree.delete(row)

        search_text = self.search_var.get().lower()

        rules = self.firewall.get_rules()
        for rule in rules:
            rule_values = (
                rule.get("rule_id"),
                rule.get("action"),
                rule.get("source_ip"),
                rule.get("destination_ip"),
                rule.get("protocol"),
                rule.get("source_port"),
                rule.get("destination_port"),
                rule.get("hit_count"),
                "Yes" if rule.get("enabled", True) else "No",
                rule.get("description", "")
            )

            if search_text:
                # Filter rules based on search text
                if not any(search_text in str(value).lower() for value in rule_values):
                    continue

            tag = ""
            if not rule.get("enabled", True):
                tag = "disabled"
            elif rule.get("action") == "allow":
                tag = "allow"
            elif rule.get("action") == "block":
                tag = "block"

            self.tree.insert("", tk.END, values=rule_values, tags=(tag,))

        # Tag colors
        self.tree.tag_configure("allow", background="#d4f4dd")
        self.tree.tag_configure("block", background="#f4d4d4")
        self.tree.tag_configure("disabled", background="#e0e0e0")

    def add_rule_popup(self):
        popup = tk.Toplevel(self.window)
        popup.title("Add Firewall Rule")
        popup.geometry("400x500")
        popup.transient(self.window)

        entries = {}

        fields = ["Action (allow/block)", "Source IP", "Destination IP", "Protocol (TCP/UDP/ICMP/any)", 
                  "Source Port", "Destination Port", "Description"]

        for idx, field in enumerate(fields):
            ttk.Label(popup, text=field).pack(pady=2)
            entry = ttk.Entry(popup)
            entry.pack(fill=tk.X, padx=10)
            entries[field] = entry

        def save_rule():
            action = entries["Action (allow/block)"].get().strip().lower()
            if action not in ["allow", "block"]:
                messagebox.showerror("Error", "Action must be 'allow' or 'block'.")
                return

            rule = {
                "action": action,
                "source_ip": entries["Source IP"].get() or "any",
                "destination_ip": entries["Destination IP"].get() or "any",
                "protocol": entries["Protocol (TCP/UDP/ICMP/any)"].get() or "any",
                "source_port": entries["Source Port"].get() or "any",
                "destination_port": entries["Destination Port"].get() or "any",
                "description": entries["Description"].get() or ""
            }

            self.firewall.add_rule(rule)
            self.load_rules()
            popup.destroy()

        ttk.Button(popup, text="Save", command=save_rule).pack(pady=10)

    def delete_rule(self):
        selected = self.tree.selection()
        if not selected:
            messagebox.showwarning("Warning", "Select a rule to delete.")
            return

        rule_id = self.tree.item(selected[0])['values'][0]
        if messagebox.askyesno("Confirm", f"Delete rule {rule_id}?"):
            self.firewall.delete_rule(rule_id)  # 🔥 correct function
            self.load_rules()  # 🔥 refresh table



    def toggle_rule(self):
        selected = self.tree.selection()
        if not selected:
            messagebox.showwarning("Warning", "Select a rule to enable/disable.")
            return

        rule_id = self.tree.item(selected[0])['values'][0]
        self.firewall.toggle_rule(rule_id)
        self.load_rules()

    def refresh_hit_counts(self):
        self.load_rules()
        self.window.after(3000, self.refresh_hit_counts)

    def export_rules(self):
        file_path = filedialog.asksaveasfilename(defaultextension=".json",
                                                 filetypes=[("JSON files", "*.json")])
        if not file_path:
            return

        try:
            rules = self.firewall.get_rules()
            with open(file_path, 'w') as f:
                json.dump(rules, f, indent=4)
            messagebox.showinfo("Export", "Firewall rules exported successfully.")
        except Exception as e:
            messagebox.showerror("Error", f"Failed to export rules.\n{e}")

    def import_rules(self):
        file_path = filedialog.askopenfilename(filetypes=[("JSON files", "*.json")])
        if not file_path:
            return

        try:
            with open(file_path, 'r') as f:
                rules = json.load(f)
            if isinstance(rules, list):
                self.firewall.import_rules(rules)
                self.load_rules()
                messagebox.showinfo("Import", "Firewall rules imported successfully.")
            else:
                messagebox.showerror("Error", "Invalid firewall rules format.")
        except Exception as e:
            messagebox.showerror("Error", f"Failed to import rules.\n{e}")
