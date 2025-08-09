from scapy.all import IP, TCP, sr1
import time
#key in IP address and port range
target_ip = input("Enter IP address: ") 
port_range_start = int(input("Enter first port: "))
port_range_end = int(input("Enter last port: "))

print(f"Starting TCP SYN scan on {target_ip}...")

def portscan(target_ip, port_range_start, port_range_end):
    open_ports = []
    for port in range(port_range_start, port_range_end + 1):
        #send syn packet
        pkt = IP(dst = target_ip)/TCP(dport=port, flags="S") 
        response = sr1(pkt, timeout=1, verbose=0)

        if response:
            #interpret response SYN-ACK (0x12) → Port is open.
            if response.haslayer(TCP) and response.getlayer(TCP).flags == 0x12: 
                open_ports.append(port)
                # Send RST to close connection and avoid half-open connections
                sr1(IP(dst=target_ip)/TCP(dport=port, flags="R"), timeout=1, verbose=0)
                print(f"Port {port} is OPEN")
        else:
            print(f"Port {port} is FILTERED or no response")

    return open_ports

open = portscan(target_ip, port_range_start, port_range_end)
