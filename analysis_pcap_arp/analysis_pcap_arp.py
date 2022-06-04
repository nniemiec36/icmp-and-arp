import dpkt as dp
import sys

packets = []
arp_packets = []
arp_req = []
arp_res = []

def read_pcap_arp(pcap):
    for ts, buf in pcap:
        packets.append(buf)
        if buf[12:14] == b'\x08\x06':
            arp_packets.append(buf)
            if buf[0:6] != b'\xff\xff\xff\xff\xff\xff':
                if buf[20:22] != b'\x00\x01':
                    arp_res.append(buf)
                else:
                    arp_req.append(buf)


def print_first_arp_exchange():
    # check if there is an exchange that exists
    if len(arp_req) == 0:
        print("There are no ARP requests recorded.")
    if len(arp_res) == 0:
        print("There are no ARP responses recorded.")
    
    if len(arp_req) != 0 and len(arp_res) != 0:
        print_arp_exchange()

def print_arp_exchange():

    print("ARP request-response exchange information:\n")
    res = arp_res[0]
    req = arp_req[0]
    print("------ARP REQUEST:")
    print("Header info:")
    print("Hardware Type: " + str(int.from_bytes(req[14:16], "big")))
    print("Protocol Type: 0x" + str(req[16:18].hex()))
    print("Hardware Size: " + str(req[18]))
    print("Protocol Size: " + str(req[19]))
    print("Opcode: request (" + str(int.from_bytes(req[20:22], "big")) + ")")
    sender_mac_addr = get_mac_address(req[22:28].hex())
    print("Sender MAC Address: " + sender_mac_addr[:-1])
    sender_ip = get_ip_address(req[28:32])
    print("Sender IP Address: " + sender_ip[:-1])
    target_mac_addr = get_mac_address(req[32:38].hex())
    print("Target MAC Address: " + target_mac_addr[:-1])
    target_ip = get_ip_address(req[38:42])
    print("Target IP Address: " + target_ip[:-1])
    print("\n------ARP RESPONSE:")
    print("Hardware Type: " + str(int.from_bytes(res[14:16], "big")))
    print("Protocol Type: 0x" + str(res[16:18].hex()))
    print("Hardware Size: " + str(res[18]))
    print("Protocol Size: " + str(res[19]))
    print("Opcode: response (" + str(int.from_bytes(res[20:22], "big")) + ")")
    sender_mac_addr = get_mac_address(res[22:28].hex())
    print("Sender MAC Address: " + sender_mac_addr[:-1])
    sender_ip = get_ip_address(res[28:32])
    print("Sender IP Address: " + sender_ip[:-1])
    target_mac_addr = get_mac_address(res[32:38].hex())
    print("Target MAC Address: " + target_mac_addr[:-1])
    target_ip = get_ip_address(req[38:42])
    print("Target IP Address: " + target_ip[:-1])


def get_mac_address(address): # referenced from dpkt docs
    """Convert a MAC address to a readable/printable string

       Args:
           address (str): a MAC address in hex form (e.g. '\x01\x02\x03\x04\x05\x06')
       Returns:
           str: Printable/readable MAC address
    """
    mac_address = ""
    count = 0
    for i in address:
        mac_address += str(i)
        count += 1
        if count == 2:
            mac_address += ":"
            count = 0 # reset count
    return mac_address

def get_ip_address(address):
    ip_addr = ""
    for i in address:
        ip_addr += str(i) + "."

    return ip_addr    


def main():
    file_name = sys.argv[1]
    pcap = ".pcap"
    try: 
        if pcap not in file_name:
            raise Exception("Not a valid pcap file name.")
        else:
            file = open(file_name, 'rb')
            pcap = dp.pcap.Reader(file)
            read_pcap_arp(pcap)
            print_first_arp_exchange()
    except FileNotFoundError:
        print("Please enter a valid pcap file name.")

if __name__ == '__main__':
    try:
        main()
    except:
        print("Please enter a valid pcap file name.")
