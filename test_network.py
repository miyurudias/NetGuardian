from scapy.all import get_if_list

print("Available network interfaces:")

for interface in get_if_list():
    print(interface)