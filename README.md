# SNI-Leak-PoC
This is a very simple script that sniff SNI request and parse the leaked domains in an output file. 
This script is made for showing the information leak that remains in the TLS protocole and more precisly in the SNI extension.

There's 2 versions of the script:
1. ```SNI_Pcap_Scanner.py``` -> Let you scan a .pcap file to extract the leaked domains from it. (Only CLI Output !)

2. ```SNI_Sniffer.py``` -> Let you sniff your trafic live to extract the leaked domain directly while your browsing and parse them in the ```output.txt``` file.


# **Installation**

1. ```pip3 install -r requirements.txt```

2. You can edit ```iface=""``` and uncomment the lines 9 and 39 to sniff from a specific eth card. **(Only if needed. Skip this step if you don't understand what it's about !)**

3. MacOS: ```python3 main.py```
   Windows: ```py main.py```


# Screenshots

   
![Capture d’écran 2023-07-10 171016](https://github.com/xHaash/SNI-Leak-PoC/assets/106975735/1e0eb9f8-241f-4d89-b0c8-2cc3ae4d6681)
![Capture d’écran 2023-07-10 171703](https://github.com/xHaash/SNI-Leak-PoC/assets/106975735/3b2bb771-5788-4a6c-8766-378e5f16e850)
