# firewall.py

import json
import ipaddress
import threading
import os
from datetime import datetime

class Firewall:
    def __init__(self, rules_file="firewall_rules.json"):
        self.rules_file = rules_file
        self.rules = []
        self.enabled = True
        self.default_action = "block"
        self.load()

    def load(self):
        try:
            with open(self.rules_file, 'r') as f:
                data = json.load(f)
                self.enabled = data.get("enabled", True)
                self.default_action = data.get("default_action", "block")
                self.rules = data.get("rules", [])
        except Exception as e:
            print(f"Failed to load firewall rules: {e}")
            self.rules = []

    def save(self):
        try:
            with open(self.rules_file, 'w') as f:
                json.dump({
                    "enabled": self.enabled,
                    "default_action": self.default_action,
                    "rules": self.rules
                }, f, indent=4)
        except Exception as e:
            print(f"Failed to save firewall rules: {e}")

    def get_rules(self):
        return self.rules

    def delete_rule(self, rule_id):
        """Delete a firewall rule by rule_id."""
        before = len(self.rules)
        # 🔥 VERY IMPORTANT: convert both sides to string
        self.rules = [rule for rule in self.rules if str(rule.get("rule_id")) != str(rule_id)]
        after = len(self.rules)

        if before != after:
            print(f"Deleted rule {rule_id} (before={before}, after={after})")
            self.save()
        else:
            print(f"No rule found with ID {rule_id} to delete.")

    def add_rule(self, rule_data):
        rule_data["rule_id"] = datetime.datetime.now().strftime("%Y%m%d%H%M%S")
        rule_data["enabled"] = True
        rule_data["hit_count"] = 0
        rule_data["created"] = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        self.rules.append(rule_data)
        self.save()

    def toggle_rule(self, rule_id):
        for rule in self.rules:
            if str(rule.get("rule_id")) == str(rule_id):
                rule["enabled"] = not rule.get("enabled", True)
                self.save()
                return
    def get_rules(self):
        return self.rules

    def import_rules(self, rules_list):
        for rule in rules_list:
            if "rule_id" not in rule:
                rule["rule_id"] = datetime.datetime.now().strftime("%Y%m%d%H%M%S")
            rule["hit_count"] = rule.get("hit_count", 0)
            rule["enabled"] = rule.get("enabled", True)
            rule["created"] = rule.get("created", datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"))
            self.rules.append(rule)
        self.save()

    def __init__(self, rules_path="firewall_rules.json"):
        self.rules_path = rules_path
        self.rules_data = {
            "enabled": False,
            "default_action": "block",
            "rules": []
        }
        self.lock = threading.Lock()
        self.load_rules()

    def load_rules(self):
        if not os.path.exists(self.rules_path):
            self.save_rules()
        try:
            with open(self.rules_path, "r") as f:
                self.rules_data = json.load(f)
        except Exception as e:
            print(f"Failed to load firewall rules: {e}")

    def save_rules(self):
        with self.lock:
            try:
                with open(self.rules_path, "w") as f:
                    json.dump(self.rules_data, f, indent=4)
            except Exception as e:
                print(f"Failed to save firewall rules: {e}")

    def is_enabled(self):
        return self.rules_data.get("enabled", False)

    def default_action(self):
        return self.rules_data.get("default_action", "block")

    def get_rules(self):
        return self.rules_data.get("rules", [])

    def match_packet(self, src_ip, dst_ip, protocol, src_port=None, dst_port=None):
        """Return True if allowed, False if blocked."""
        if not self.is_enabled():
            return True  # Firewall disabled

        for rule in self.get_rules():
            if not rule.get("enabled", True):
                continue

            if not self.match_ip(rule.get("source_ip", "any"), src_ip):
                continue

            if not self.match_ip(rule.get("destination_ip", "any"), dst_ip):
                continue

            if not self.match_protocol(rule.get("protocol", "any"), protocol):
                continue

            if not self.match_port(rule.get("source_port", "any"), src_port):
                continue

            if not self.match_port(rule.get("destination_port", "any"), dst_port):
                continue

            # Rule matched!
            rule["hit_count"] = rule.get("hit_count", 0) + 1
            self.save_rules()
            return rule.get("action", "block") == "allow"

        # No matching rule found, apply default action
        return self.default_action() == "allow"

    def match_ip(self, rule_ip, packet_ip):
        if rule_ip == "any":
            return True
        try:
            if "/" in rule_ip:
                network = ipaddress.ip_network(rule_ip, strict=False)
                return ipaddress.ip_address(packet_ip) in network
            else:
                return rule_ip == packet_ip
        except Exception:
            return False

    def match_protocol(self, rule_proto, packet_proto):
        if rule_proto == "any":
            return True
        return rule_proto.lower() == packet_proto.lower()

    def match_port(self, rule_port, packet_port):
        if rule_port == "any" or packet_port is None:
            return True
        try:
            if "-" in str(rule_port):
                start, end = map(int, rule_port.split("-"))
                return start <= int(packet_port) <= end
            else:
                return int(rule_port) == int(packet_port)
        except Exception:
            return False

    def set_enabled(self, enabled):
        self.rules_data["enabled"] = enabled
        self.save_rules()

    def set_default_action(self, action):
        if action in ["allow", "block"]:
            self.rules_data["default_action"] = action
            self.save_rules()

    def update_rule(self, rule_id, updated_rule):
        for rule in self.get_rules():
            if rule.get("rule_id") == rule_id:
                rule.update(updated_rule)
                break
        self.save_rules()

    def reset_hit_counts(self):
        for rule in self.get_rules():
            rule["hit_count"] = 0
        self.save_rules()

if __name__ == "__main__":
    # Simple test
    fw = Firewall()
    print(f"Firewall enabled: {fw.is_enabled()}")
    result = fw.match_packet("192.168.1.5", "8.8.8.8", "TCP", src_port=12345, dst_port=80)
    print(f"Packet allowed: {result}")
