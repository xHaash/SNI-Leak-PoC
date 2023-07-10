from scapy.all import *
import cryptography

# Starting at 1 because wireshark iterating start at 1 not 0.
i = 1

load_layer("tls")

cap = rdpcap('ClientHello.pcapng')

while i < len(cap):
    packet=cap[i]
    
    if "TLS Handshake - Client Hello" in str(packet):
        print("[+] Found Packet n°" + str(i) + " -> Containing a Client Hello !\n")
        print("[+] Packet info: " + str(packet) + "\n")
        
        
        pkt_infos = packet.show(dump=True)
        for line in pkt_infos.splitlines():
            if "servernames=" in line:
                print("[+] Domain Leaked: " + str(line.strip("[]''=")[35:len(line)]) + "\n")
        print("==================================================\n")
    
    
    i += 1
    
 