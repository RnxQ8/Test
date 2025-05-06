from scapy.all import ARP, Ether, srp
import sys

def scan_network(ip_range):
    # Create an Ethernet frame with an ARP request
    arp_request = ARP(pdst=ip_range)
    broadcast = Ether(dst="ff:ff:ff:ff:ff:ff")
    packet = broadcast / arp_request

    print(f"Scanning network: {ip_range}...\n")
    result = srp(packet, timeout=2, verbose=0)[0]

    devices = []
    for sent, received in result:
        devices.append({'ip': received.psrc, 'mac': received.hwsrc})

    return devices

def print_devices(devices):
    print("Available devices on the network:")
    print("IP Address\t\tMAC Address")
    print("-----------------------------------------")
    for device in devices:
        print(f"{device['ip']}\t\t{device['mac']}")

if __name__ == "__main__":
    print("Wifi Eye By RNX")
    if len(sys.argv) != 2:
        print("Usage: sudo python3 wifi_eye.py <IP_RANGE>")
        print("Example: sudo python3 wifi_eye.py 192.168.1.0/24")
        sys.exit(1)

    ip_range = sys.argv[1]
    devices = scan_network(ip_range)
    print_devices(devices)
