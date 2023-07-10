from scapy.all import *
import cryptography
from datetime import datetime


load_layer("tls")

# If you need to configure a specific eth card: Change the value of the "iface" variable then uncomment the code from l.9 & l.39 and comment the l.38 :)
#iface = "eth0"

# Packet process function
def process_packet(packet):
    if "TLS Handshake - Client Hello" in str(packet):
        print("==================================================")
        dt = datetime.now()
        print("\n[+] Found Packet Containing a Client Hello !\n")
        print("[+] Time: " + str(dt))
        print("\n[+] Packet info: " + str(packet) + "\n")
        
        pkt_infos = packet.show(dump=True)
        for line in pkt_infos.splitlines():
            if "servernames=" in line:
                domain = str(line.strip("[]''=")[35:len(line)])
                if domain:
                    print("[+] Domain Leaked: " + domain + "\n")

                    ip_routing = str(packet).split("/")
                    with open("output.txt", "a") as f:
                        print(str(dt) + " | " + ip_routing[3][5:] + "| " + domain, file=f)

                else:
                    print("[-] No Domain Found !")
            

# Fonction principale
def start_sniffing():
    print("[+] Start Sniffing...\n")
    sniff(filter="tcp port 443", prn=process_packet)
    #sniff(iface="Ethernet", filter="tcp port 443", prn=process_packet)


# Lancement du script
if __name__ == '__main__':
    start_sniffing()
