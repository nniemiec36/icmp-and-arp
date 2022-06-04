# ARP Packet Capture and Analysis

## Program and Libraries used
 Program used:
 * Python ver. 3.8.4

 Library used:
 * dpkt [Link - https://pypi.org/project/dpkt/]
 * sys [Link - https://docs.python.org/3.8/library/sys.html]

## PCAP Programming Task and flow-level information
To use this program:
Execute the program analysis_pcap_tcp.py on the terminal as:
python3 analysis_pcap_arp.py "pcapfile.pcap"
For example, if you want to analyze connections in "assignment4_my_arp.pcap":
python3 analysis_pcap_tcp.py assignment4_my_arp.pcap
it will analyze the connections made in 'assignment4_my_arp.pcap'

## Logic
After opening the pcap file with dpkt's pcap.Reader, we send this into our written method, "read_pcap_arp()". This method iterates through the file, adding all the packets found in the pcap file into a list, as well as organizing the packets into their respective lists such as arp_packets, arp_req, and arp_res. We can check if an packet is an ARP packet if the EtherType is "0x0806". We can check if it's a request packet if the OpCode is "0x0001" or a response if the OpCode is "0x0002".

After we sort the packets, we want to print out the first arp exchange. We can make sure that these are the correct corresponding request and response by comparing the IP and Mac addresses of the sender and receiver on both of the packets. 