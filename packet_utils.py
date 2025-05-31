import ipaddress
import socket
import struct
from scapy.all import send
from scapy.layers.inet import IP, ICMP

class PacketUtils:
    def __init__(self):
        try:
            self.raw_socket = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW)
        except PermissionError:
            print("Warning: Could not create raw socket. Running in simulation mode.")
            self.raw_socket = None
            self.simulation_mode = True
        else:
            self.simulation_mode = False
        
    def is_valid_packet(self, packet):
        try:
            print(f"\nValidating packet:")
            print(f"Packet attributes: {packet.fields}")
            
            # Basic validation
            if not hasattr(packet, 'src') or not hasattr(packet, 'dst'):
                print("Packet missing src or dst fields")
                return False
                
            # Check if source IP is valid
            src_ip = ipaddress.ip_address(packet.src)
            print(f"Valid source IP: {src_ip}")
            
            # Check if destination IP is valid
            dst_ip = ipaddress.ip_address(packet.dst)
            print(f"Valid destination IP: {dst_ip}")
            
            print("Packet validation successful")
            return packet.haslayer(IP)
        except Exception as e:
            print(f"Packet validation failed: {e}")
            import traceback
            traceback.print_exc()
            return False
            
    def check_ttl(self, packet):
        try:
            if hasattr(packet, 'ttl'):
                print(f"Checking TTL: {packet.ttl}")
                return packet.ttl <= 1
            print("Packet has no TTL field")
            return False
        except Exception as e:
            print(f"Error checking TTL: {e}")
            return False
        
    def decrement_ttl(self, packet):
        try:
            if hasattr(packet, 'ttl'):
                print(f"Decrementing TTL from {packet.ttl}")
                packet.ttl -= 1
                # Recalculate checksum
                del packet.chksum
                packet = packet.__class__(bytes(packet))
                print(f"New TTL: {packet.ttl}")
            return packet
        except Exception as e:
            print(f"Error decrementing TTL: {e}")
            return packet
        
    def send_icmp_time_exceeded(self, original_packet):
        if self.simulation_mode:
            print(f"Simulation: Sending ICMP Time Exceeded to {original_packet.src}")
            return
            
        try:
            icmp = ICMP(type=11, code=0)  # Time Exceeded
            ip = IP(src=original_packet.dst, dst=original_packet.src)
            print(f"Sending ICMP Time Exceeded: {ip.src} -> {ip.dst}")
            send(ip/icmp/original_packet)
        except Exception as e:
            print(f"Error sending ICMP Time Exceeded: {e}")
            
    def forward_packet(self, packet, next_hop, interface):
        if self.simulation_mode:
            print(f"Simulation: Forwarding packet from {packet.src} to {next_hop} via {interface}")
            return
            
        try:
            # Decrement TTL
            packet = self.decrement_ttl(packet)
            
            # Set the destination IP to the next hop
            print(f"Setting next hop to {next_hop}")
            packet.dst = next_hop
            
            # Send the packet
            print(f"Sending packet via {interface}")
            send(packet, iface=interface)
        except Exception as e:
            print(f"Error forwarding packet: {e}")
            import traceback
            traceback.print_exc()
        
    def create_raw_socket(self, interface):
        if self.simulation_mode:
            print(f"Simulation: Creating raw socket for interface {interface}")
            return None
            
        try:
            s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(0x0800))
            s.bind((interface, 0))
            return s
        except Exception as e:
            print(f"Error creating raw socket: {e}")
            return None