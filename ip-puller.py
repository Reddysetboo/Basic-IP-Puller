import pyshark
import socket

s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
try:
    # This doesn't actually connect or send traffic, 
    # it just uses the target address to find the right network interface
    s.connect(('8.8.8.8', 1))
    ipv4 = s.getsockname()[0]
except Exception:
    ipv4 = '127.0.0.1' # Fallback to localhost if not connected to a network
finally:
    s.close()

# AF_INET6 specifies we are looking for IPv6
s = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM)
try:
    # A dummy connection to Google's public IPv6 DNS
    s.connect(('2001:4860:4860::8888', 1))
    ipv6 = s.getsockname()[0]
except Exception:
    ipv6 = '::1' # Fallback to IPv6 localhost (equivalent to 127.0.0.1)
finally:
    s.close()

interface_type = input("Please input interface type (CASE SENSITIVE): ")

capture = pyshark.LiveCapture(interface=interface_type, display_filter="stun.type == 0x0101")

print(f"\nListening for STUN traffic on {interface_type}... Press Ctrl+C to stop.\n")

try:
    for packet in capture.sniff_continuously():
        try:
            if 'IP' in packet:
                print(packet.ip.src, " -> ", packet.ip.dst)
                if not packet.ip.src == ipv4:
                    captured_ip_src = packet.ip.src
                    print("Captured!")
                    try:
                        with open("ip-list.txt", "r") as file:
                            existing_lines = file.readlines()
                    except FileNotFoundError:
                        existing_lines = []

                    if captured_ip_src not in existing_lines:
                        with open("ip-list.txt", "a") as file:
                            file.write(f"\n{captured_ip_src}")
                    else:
                        print("IP already exists. Skipping.")
                else:
                    continue
                if not packet.ip.dst == ipv4:
                    captured_ip_dst = packet.ip.dst
                    try:
                        with open("ip-list.txt", "r") as file:
                            existing_lines = file.readlines()
                    except FileNotFoundError:
                        existing_lines = []

                    if captured_ip_dst not in existing_lines:
                        with open("ip-list.txt", "a") as file:
                            file.write(f"\n{captured_ip_dst}")
                    else:
                        print("IP already exists. Skipping.")
                else:
                    continue
            elif 'IPV6' in packet:
                print(packet.ipv6.src, " -> ", packet.ipv6.dst)
                if not packet.ipv6.src == ipv6:
                    captured_ipv6_src = packet.ipv6.src
                    print("Captured!")
                    try:
                        with open("ip-list.txt", "r") as file:
                            existing_lines = file.readlines()
                    except FileNotFoundError:
                        existing_lines = []

                    if captured_ipv6_src not in existing_lines:
                        with open("ip-list.txt", "a") as file:
                            file.write(f"\n{captured_ipv6_src}")
                    else:
                        print("IP already exists. Skipping.")
                else:
                    continue
                if not packet.ipv6.dst == ipv6:
                    captured_ipv6_dst = packet.ipv6.dst
                    try:
                        with open("ip-list.txt", "r") as file:
                            existing_lines = file.readlines()
                    except FileNotFoundError:
                        existing_lines = []

                    if captured_ipv6_dst not in existing_lines:
                        with open("ip-list.txt", "a") as file:
                            file.write(f"\n{captured_ipv6_dst}")
                    else:
                        print("IP already exists. Skipping.")
                else:
                    continue
        except AttributeError:
            continue

except KeyboardInterrupt:
    print("\nStopping capture.")



