import json
import socket
import struct
from scapy.all import *
from scapy.layers.l2 import Ether
from packet_utils import PacketUtils
import ipaddress
import threading
import time
from scapy.layers.inet import IP, ICMP, TCP, UDP
from scapy.layers.l2 import ARP
from datetime import datetime
import random
import os
from scapy.all import sniff
from typing import Dict, List, Optional
from firewall import Firewall

class SimulatedPacket:
    """Enhanced simulated packet with more realistic attributes that can be converted to Scapy"""
    def __init__(self, src=None, dst=None, ttl=None, protocol=None):
        self.src = src or "192.168.1.1"
        self.dst = dst or "192.168.1.2"
        self.ttl = ttl or random.randint(32, 64)
        self.protocol = protocol or "Other"
        self.size = self._get_default_size()
        self.id = random.randint(1000, 65000)
        self.timestamp = datetime.now()
        # Create a scapy equivalent for export - delayed initialization to avoid circular reference
        self._scapy_packet = None
        
    def _get_default_size(self):
        """Return realistic packet size based on protocol"""
        sizes = {
            "ICMP": random.randint(56, 84),
            "TCP": random.randint(40, 1500),
            "UDP": random.randint(28, 1470),
            "ARP": 28,
            "Other": random.randint(50, 800)
        }
        return sizes.get(self.protocol, 64)
    
    def _create_scapy_packet(self):
        """Create a Scapy packet equivalent for this simulated packet"""
        try:
            # Start with IP layer
            ip_pkt = IP(src=self.src, dst=self.dst, ttl=self.ttl, id=self.id)
            
            # Add appropriate protocol layer
            if self.protocol == "ICMP":
                # Create ICMP echo request
                return ip_pkt/ICMP(type=8, code=0, id=self.id)
            elif self.protocol == "TCP":
                # Create TCP packet with random ports
                src_port = random.randint(1024, 65000)
                dst_port = random.choice([80, 443, 22, 8080, 8443, 3389])
                return ip_pkt/TCP(sport=src_port, dport=dst_port)
            elif self.protocol == "UDP":
                # Create UDP packet with random ports
                src_port = random.randint(1024, 65000)
                dst_port = random.choice([53, 123, 161, 1900, 5353])
                return ip_pkt/UDP(sport=src_port, dport=dst_port)
            elif self.protocol == "ARP":
                # For ARP, return just the ARP packet
                return Ether()/ARP(psrc=self.src, pdst=self.dst)
            else:
                # For other protocols, just return the IP packet
                return ip_pkt
        except Exception as e:
            print(f"Error creating Scapy packet: {e}")
            # Return a simple IP packet as fallback
            return IP(src=self.src, dst=self.dst)
            
    def to_scapy(self):
        """Return the Scapy equivalent of this packet"""
        # Lazy initialization of Scapy packet
        if self._scapy_packet is None:
            self._scapy_packet = self._create_scapy_packet()
        return self._scapy_packet
    
    def __str__(self):
        return f"SimPacket({self.protocol}): {self.src} -> {self.dst}, TTL:{self.ttl}"


class VirtualRouter:
    def start_sniffing(self):
        if not self.sniffing_interface:
            self.log_event("No sniffing interface set. Cannot start sniffing.", "ERROR")
            return

        try:
            self.log_event(f"Starting packet capture on {self.sniffing_interface} (IP packets only)")
            sniff(
                iface=self.sniffing_interface,
                prn=self.process_packet,
                store=False,
                filter="ip",   # 🚀 Only capture IP packets!
                promisc=True
            )
        except Exception as e:
            self.log_event(f"Error sniffing packets: {e}", "ERROR")
            
    def sniff_packets(self):
        def callback(packet):
            self.process_packet(packet)

        self.log_event(f"Started sniffing on interface: {self.sniffing_interface}")
        sniff(iface=self.sniffing_interface, prn=callback, store=False)

    def generate_simulated_packet(self):
        """Generate a realistic simulated packet based on the routing table"""
        if not self.routing_table["routes"]:
            return None  # No routes to simulate
            
        # 60% chance to use an existing route, 40% random
        if random.random() < 0.6 and self.routing_table["routes"]:
            # Use an existing route
            route = random.choice(self.routing_table["routes"])
            
            try:
                # Create a network from the route
                if route['subnet'] == "0":  # Handle default route
                    # For default routes, use random IPs
                    src_ip = f"192.168.{random.randint(1, 254)}.{random.randint(1, 254)}"
                    dst_ip = f"10.{random.randint(1, 254)}.{random.randint(1, 254)}.{random.randint(1, 254)}"
                else:
                    # For specific routes, use IPs within the subnet
                    net = ipaddress.ip_network(f"{route['destination']}/{route['subnet']}", strict=False)
                    hosts = list(net.hosts())
                    
                    if len(hosts) < 2:  # Handle /31 or /32 subnets
                        src_ip = str(net.network_address)
                        dst_ip = route['next_hop']
                    else:
                        src_ip = str(random.choice(hosts))
                        # 80% chance to be in same subnet, 20% outside
                        if random.random() < 0.8:
                            dst_ip = str(random.choice(hosts))
                        else:
                            dst_ip = route['next_hop']
            except Exception as e:
                # Fallback if network calculation fails
                self.log_event(f"Error generating IP from route: {e}", "WARNING")
                src_ip = f"192.168.{random.randint(1, 254)}.{random.randint(1, 254)}"
                dst_ip = route['next_hop']
        else:
            # Generate completely random packet
            src_ip = f"192.168.{random.randint(1, 254)}.{random.randint(1, 254)}"
            dst_ip = f"10.{random.randint(1, 254)}.{random.randint(1, 254)}.{random.randint(1, 254)}"
        
        # Create the packet with realistic protocol distribution
        protocol_weights = {
            "TCP": 0.65,  # Most common
            "UDP": 0.20,
            "ICMP": 0.10,
            "ARP": 0.03,
            "Other": 0.02
        }
        
        protocols = list(protocol_weights.keys())
        weights = list(protocol_weights.values())
        protocol = random.choices(protocols, weights=weights, k=1)[0]
        
        # Create packet with realistic TTL
        ttl_values = {
            64: 0.7,    # Linux/Unix default
            128: 0.25,  # Windows default
            255: 0.05   # Some network devices
        }
        ttl_options = list(ttl_values.keys())
        ttl_weights = list(ttl_values.values())
        base_ttl = random.choices(ttl_options, weights=ttl_weights, k=1)[0]
        
        # Adjust TTL with some randomness to simulate hops
        final_ttl = max(1, base_ttl - random.randint(0, 20))
        
        return SimulatedPacket(src=src_ip, dst=dst_ip, ttl=final_ttl, protocol=protocol)

    def __init__(self, routing_table_path="routing_table.json", ttl_min=32, ttl_max=64):
        self.routing_table_path = routing_table_path
        self.logs = []
        self.stats = {
            "forwarded": 0,
            "dropped": 0,
            "ttl_expired": 0,
            "source_invalid": 0,
            "no_route": 0,
            "total_processed": 0,
            "packet_types": {
                "ICMP": 0,
                "TCP": 0,
                "UDP": 0,
                "ARP": 0,
                "Other": 0
            }
        }

        self.running = False
        self.simulation_thread = None
        self.route_update_lock = threading.Lock()
        self.packet_utils = PacketUtils()
        
        self.ttl_min = ttl_min
        self.ttl_max = ttl_max
        self.captured_packets = []
        self.capture_enabled = True
        self.loss_simulation_enabled = True
        self.last_priority_aging = time.time()
        self.aging_thread = None
        self.sniffing_interface = None
        self.simulation_speed = 1.0  # Packets per second
        self.firewall = Firewall()

        self.routing_table = self.load_routing_table(routing_table_path)
        self.log_event(f"Initialized router with {len(self.routing_table['routes'])} routes")
    
    def log_event(self, message, level="INFO"):
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S.%f")[:-3]
        log_entry = f"[{timestamp}] {level}: {message}"
        print(log_entry)
        self.logs.append(log_entry)
        if len(self.logs) > 200:  # Limit to last 200 logs to avoid GUI freeze
            self.logs = self.logs[-200:]
    
    def get_logs(self):
        return self.logs
    
    def get_stats(self):
        stats_copy = self.stats.copy()
        stats_copy["total_processed"] = (
            self.stats["forwarded"] + self.stats["dropped"]
        )
        return stats_copy

    def load_routing_table(self, path):
        try:
            self.log_event(f"Loading routing table from {path}")
            with open(path, 'r') as f:
                table = json.load(f)
            if not isinstance(table, dict) or 'routes' not in table:
                self.log_event("Invalid routing table format. Creating new table.", "WARNING")
                return {"routes": []}
            for route in table['routes']:
                if "last_used" not in route:
                    route["last_used"] = None
            return table
        except (FileNotFoundError, json.JSONDecodeError):
            self.log_event("Routing table load failed, creating new one.", "WARNING")
            return {"routes": []}
    
    def save_routing_table(self):
        with self.route_update_lock:
            try:
                with open(self.routing_table_path, 'w') as f:
                    json.dump(self.routing_table, f, indent=4)
                self.log_event(f"Routing table saved with {len(self.routing_table['routes'])} routes")
                return True
            except Exception as e:
                self.log_event(f"Error saving routing table: {e}", "ERROR")
                return False
    
    def add_route(self, destination, subnet, next_hop, interface, priority=100, cost=1):
        try:
            ipaddress.ip_address(destination)
            ipaddress.ip_address(next_hop)
            subnet_int = int(subnet)
            if not 0 <= subnet_int <= 32:
                raise ValueError("Subnet must be 0-32")
            
            for r in self.routing_table["routes"]:
                if r["destination"] == destination and r["subnet"] == subnet and r["interface"] == interface:
                    self.log_event(f"Duplicate route {destination}/{subnet} via {interface}", "WARNING")
                    return False
            
            route_entry = {
                "destination": destination,
                "subnet": subnet,
                "next_hop": next_hop,
                "interface": interface,
                "cost": cost,
                "priority": priority,
                "last_used": None
            }
            self.routing_table["routes"].append(route_entry)
            return self.save_routing_table()
        
        except Exception as e:
            self.log_event(f"Error adding route: {e}", "ERROR")
            return False
    
    def delete_route(self, destination, subnet=None):
        initial = len(self.routing_table["routes"])
        self.routing_table["routes"] = [
            r for r in self.routing_table["routes"]
            if not (r["destination"] == destination and (subnet is None or r["subnet"] == str(subnet)))
        ]
        if len(self.routing_table["routes"]) < initial:
            self.save_routing_table()
            return True
        else:
            self.log_event(f"No matching route for delete: {destination}/{subnet}", "WARNING")
            return False

    def find_route(self, dest_ip):
        """Find the best route for a destination IP using longest prefix match"""
        if not dest_ip:
            return None
            
        best_match = None
        longest_prefix = -1
        highest_priority = float('inf')
        
        for route in self.routing_table["routes"]:
            try:
                network = ipaddress.ip_network(f"{route['destination']}/{route['subnet']}", strict=False)
                priority = int(route.get("priority", 100))
                
                # Check if the destination IP is in this network
                if ipaddress.ip_address(dest_ip) in network:
                    prefix_len = int(route["subnet"])
                    
                    # First check priority (lower is better)
                    # If same priority, use the longest prefix match
                    if (priority < highest_priority) or (priority == highest_priority and prefix_len > longest_prefix):
                        best_match = route
                        longest_prefix = prefix_len
                        highest_priority = priority
            except Exception as e:
                continue
                
        # Update last used timestamp if we found a route
        if best_match:
            best_match["last_used"] = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            
        return best_match
    
    def process_packet(self, packet):
        """Process a packet (either real or simulated)"""
        try:
            # Determine if this is a real Scapy packet or our simulated packet
            is_simulated = isinstance(packet, SimulatedPacket)

            # Store packet information
            if is_simulated:
                src_ip = packet.src
                dst_ip = packet.dst
                ttl = packet.ttl
                protocol = packet.protocol
                src_port = None
                dst_port = None
            else:
                # For real Scapy packets
                if not hasattr(packet, 'src') or not hasattr(packet, 'dst'):
                    self.stats["dropped"] += 1
                    self.log_event("Dropped packet missing src/dst", "WARNING")
                    return

                src_ip = getattr(packet, 'src', 'unknown')
                dst_ip = getattr(packet, 'dst', 'unknown')
                ttl = getattr(packet, 'ttl', 0)

                # Determine protocol
                if packet.haslayer(ICMP):
                    protocol = "ICMP"
                elif packet.haslayer(TCP):
                    protocol = "TCP"
                    src_port = packet[TCP].sport
                    dst_port = packet[TCP].dport
                elif packet.haslayer(UDP):
                    protocol = "UDP"
                    src_port = packet[UDP].sport
                    dst_port = packet[UDP].dport
                elif packet.haslayer(ARP):
                    protocol = "ARP"
                else:
                    protocol = "Other"

            # Track packet type
            self.stats["packet_types"][protocol] = self.stats["packet_types"].get(protocol, 0) + 1

            # 🔥 Firewall Check 🔥
            if hasattr(self, "firewall") and self.firewall.is_enabled():
                allowed = self.firewall.match_packet(src_ip, dst_ip, protocol, src_port, dst_port)
                if not allowed:
                    self.stats["dropped"] += 1
                    self.log_event(f"Firewall blocked: {src_ip} -> {dst_ip} ({protocol})", "WARNING")
                    return

            # Simulate 5% random packet loss if enabled
            if self.loss_simulation_enabled and random.random() < 0.05:
                self.stats["dropped"] += 1
                self.log_event(f"Simulated random packet loss: {src_ip} -> {dst_ip}", "WARNING")
                return

            # TTL Check
            if ttl <= 1:
                self.stats["ttl_expired"] += 1
                self.log_event(f"TTL expired: {src_ip} -> {dst_ip}", "WARNING")
                return

            # Route lookup
            route = self.find_route(dst_ip)
            if not route:
                self.stats["no_route"] += 1
                self.stats["dropped"] += 1
                self.log_event(f"No route to host: {dst_ip}", "WARNING")
                return

            # Store in the captured packets list if enabled
            if self.capture_enabled and len(self.captured_packets) < 1000:
                self.captured_packets.append(packet)

            # Handle TTL decrement
            if is_simulated:
                packet.ttl -= 1
                scapy_pkt = packet.to_scapy()
                if hasattr(scapy_pkt, 'ttl'):
                    scapy_pkt.ttl = packet.ttl
            else:
                packet.ttl -= 1
                if hasattr(packet, 'chksum'):
                    del packet.chksum
                    packet = packet.__class__(bytes(packet))

            # Forward the packet
            if is_simulated:
                self.log_event(f"Forwarded: {src_ip} -> {dst_ip} via {route['next_hop']} ({protocol})")
            else:
                try:
                    if hasattr(packet, 'build'):
                        sendp(Ether() / packet, iface=route["interface"], verbose=False)
                        self.log_event(f"Forwarded real packet to {route['next_hop']} via {route['interface']}")
                except Exception as e:
                    self.log_event(f"Failed to forward real packet: {e}", "ERROR")
                    self.stats["dropped"] += 1
                    return

            # Update statistics
            self.stats["forwarded"] += 1

        except Exception as e:
            self.stats["dropped"] += 1
            self.log_event(f"Error processing packet: {e}", "ERROR")
            import traceback
            self.log_event(traceback.format_exc(), "DEBUG")
        finally:
            self.stats["total_processed"] += 1

    def export_captured_packets(self, filename="captured_packets.pcap"):
        """Export both real and simulated packets to a PCAP file"""
        if not self.captured_packets:
            self.log_event("No packets to export", "WARNING")
            return
        
        try:
            # Create a list for export-ready packets
            export_packets = []
            simulated_count = 0
            real_count = 0
            
            # Process all packets
            for pkt in self.captured_packets:
                try:
                    if isinstance(pkt, SimulatedPacket):
                        # For simulated packets, use their Scapy equivalent
                        scapy_pkt = pkt.to_scapy()
                        if scapy_pkt:
                            export_packets.append(scapy_pkt)
                            simulated_count += 1
                    elif IP in pkt or Ether in pkt:
                        # For real Scapy packets with IP or Ethernet layer
                        export_packets.append(pkt)
                        real_count += 1
                except Exception as e:
                    self.log_event(f"Error converting packet for export: {e}", "WARNING")
                    continue
            
            if export_packets:
                # Ensure we have valid packets to write
                valid_packets = [p for p in export_packets if hasattr(p, 'build')]
                
                if valid_packets:
                    # Write PCAP file
                    wrpcap(filename, valid_packets)
                    self.log_event(f"Exported {len(valid_packets)} packets to {filename} ({simulated_count} simulated, {real_count} real)")
                    return True
                else:
                    self.log_event("No valid packets could be exported", "WARNING")
            else:
                self.log_event("No packets available for export", "WARNING")
                
            return False
                
        except Exception as e:
            self.log_event(f"Error exporting packets: {e}", "ERROR")
            import traceback
            self.log_event(traceback.format_exc(), "ERROR")
            return False
    
    def toggle_capture(self, enabled: bool):
        self.capture_enabled = enabled
        self.log_event(f"Packet capture {'enabled' if enabled else 'disabled'}")
    
    def toggle_loss_simulation(self, enabled: bool):
        self.loss_simulation_enabled = enabled
        self.log_event(f"Loss simulation {'enabled' if enabled else 'disabled'}")

    def set_sniffing_interface(self, interface: str):
        self.sniffing_interface = interface
        self.log_event(f"Sniffing interface set to {interface}")
        
    def set_simulation_speed(self, packets_per_second: float):
        """Set simulation speed in packets per second"""
        self.simulation_speed = max(0.1, min(10.0, packets_per_second))
        self.log_event(f"Simulation speed set to {self.simulation_speed} packets/second")

    def aging_priority_thread(self):
        """Thread to age route priorities based on usage"""
        while self.running:
            now = time.time()
            if now - self.last_priority_aging > 600:  # Every 10 minutes
                self.age_route_priorities()
                self.last_priority_aging = now
            time.sleep(60)  # Check every minute
    
    def age_route_priorities(self):
        """Age route priorities by increasing priority value for unused routes"""
        aged = 0
        for route in self.routing_table["routes"]:
            last_used = route.get("last_used")
            if last_used:
                last_dt = datetime.strptime(last_used, "%Y-%m-%d %H:%M:%S")
                if (datetime.now() - last_dt).total_seconds() > 600:  # 10 minutes
                    route["priority"] = int(route.get("priority", 100)) + 10
                    aged += 1
        if aged:
            self.log_event(f"Aged {aged} routes by increasing priority")
            self.save_routing_table()
            
    def start(self):
        """Start the router"""
        self.running = True
        
        # Determine mode based on whether sniffing interface is set
        if self.sniffing_interface:
            # Real packet mode
            self.log_event(f"Starting router in real packet mode on {self.sniffing_interface}")
            self.simulation_thread = threading.Thread(target=self.start_sniffing, daemon=True)
        else:
            # Simulation mode
            self.log_event("Starting router in simulation mode")
            self.simulation_thread = threading.Thread(target=self.generate_test_packets, daemon=True)
        
        self.simulation_thread.start()
        
        # Start the aging thread
        self.aging_thread = threading.Thread(target=self.aging_priority_thread, daemon=True)
        self.aging_thread.start()
        
        self.log_event("Router started successfully")

    def stop(self):
        """Stop the router"""
        self.running = False
        self.log_event("Stopping router...")
        
        # Wait for threads to finish
        if self.simulation_thread:
            self.simulation_thread.join(timeout=2)
        if self.aging_thread:
            self.aging_thread.join(timeout=2)
            
        # Save routing table before exit
        self.save_routing_table()
        self.log_event("Router stopped")

    def generate_test_packets(self):
        """Generate and process test packets at the configured rate"""
        packet_count = 0
        
        while self.running:
            try:
                # Generate a packet
                pkt = self.generate_simulated_packet()
                if pkt:
                    # Process the packet
                    self.process_packet(pkt)
                    packet_count += 1
                    
                    # Log every 10 packets
                    if packet_count % 10 == 0:
                        self.log_event(f"Generated {packet_count} simulated packets")
                    
                # Sleep according to simulation speed
                sleep_time = 1.0 / self.simulation_speed
                time.sleep(sleep_time)
                
            except Exception as e:
                self.log_event(f"Error in packet simulation: {e}", "ERROR")
                time.sleep(1)  # Recovery delay