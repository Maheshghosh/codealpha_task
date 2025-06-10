# codealpha_task
## Create a Network sniffing tool
import sys
from scapy.all import *
# function to handle each packet
def handle_packet(packet, log):
    # check if the packet contains TCP Layer
    if packet.haslayer(TCP):
       # extract source and destination ip addresses
       src_ip = packet[IP].src
       dst_ip = packet[IP].dst
       # extract source and destination port
       src_port = packet[TCP].sport
       dst_port = packet[TCP].dport
       # write packet information to log file 
       log.write(f"TCP Connection: {src_ip}:{src_port} -> {dst_ip}:{dst_port}\n")
# main funtion start 
def main(interface, verbose=False):
    # create log file name based on interface
    logfile_name = f"sniffer_{interface}_log.txt"
    # open log file for writting 
    with open(logfile_name, 'w') as logfile:
        try:
            # start packet sniffing on specified interface with verbose output
            if verbose:
                sniff(iface=interface, prn=lambda pkt: handle_packet(pkt, logfile), store=0, verbose=verbose)
            else:
                sniff(iface=interface, prn=lambda pkt: handle_packet(pkt, logfile), store=0)
        except keyboardInterrupt:
            sys.exit(0)
            

# check if the script is being run directly 
if __name__ == "__main__":
    # check if the correct number of argument is provided 
    if len(sys.argv) < 2 or len(sys.argv) > 3:
        print("usage: python sniffer.py <interface> [verbose]")
        sys.exit(1)
    # determine if verbose mode is enabled
    verbose = False
    if len(sys.argv) == 3 and sys.argv[2].lower() == "verbose":
        verbose = True
    # call the main function with the specified interface and verbose option
    main(sys.argv[1], verbose)                                     
