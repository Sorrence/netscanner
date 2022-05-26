import scapy.all as scapy
from getmac import get_mac_address as gma
import optparse

def get_user_input():
    parse_object = optparse.OptionParser()    
    parse_object.add_option("-r", "--range", dest="ip_range", help="IP range for scan")
    parse_object.add_option("-i", "--interface", dest="interface", help="Choose an interface for scan")
    
    return parse_object.parse_args()

(user_input, arguments) = get_user_input() 

def scan(ip_range, interface):
    arp_request_packet = scapy.ARP(pdst = ip_range, hwsrc=gma(interface=interface))
    broadcast_packet = scapy.Ether(src=gma(interface=interface), dst="ff:ff:ff:ff:ff:ff")
    combined_packet = broadcast_packet/arp_request_packet
    (answered_list, unanswered_list) = scapy.srp(combined_packet, timeout=1)
    answered_list.summary() 

scan(user_input.ip_range, user_input.interface)