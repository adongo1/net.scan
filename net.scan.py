#!/usr/bin/env python
import scapy.all as scapy  #Scapy is a powerful interactive packet manipulation program
import optparse

#getting arguments from useer
def get_arguments():
    parse = optparse.OptionParser()
    parse.add_option("-t", "--target", dest="ip", help="Target IP/ IP range")
    options = parse.parse_args()[0]
    return options #returing options
#funtion to scan IP
def scan(ip):

    #Address Resolution Protocol request
    arp_request = scapy.ARP(pdst=ip) #asking who has this ip

    #creating a broadcast to ask ether
    boardcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff") #default boardcast mac address

    arp_request_boardcast = boardcast/arp_request  #asking and collecting responses /answered and unanswered
    answered_list = scapy.srp(boardcast/arp_request, timeout=20, verbose=False )[0] #list only answered responses

    #creating a client_list
    client_list = []

    #in answered responds we have packets and answered
    for elements in answered_list:
        client_dict = {"ip": elements[1].psrc , "mac": elements[1].hwsrc}   #printing only answered ip  #                                                        #printing only answered mac address
        client_list.append(client_dict)
    return client_list


#funtion for printing results
def print_result(result_list):
    print("IP\t\t\tMAC Address\n -----------------------------------------")
    for client in result_list:
        print(client["ip"] + "\t\t" + client["mac"])


options = get_arguments()
scan_result = scan(options.ip)
print_result(scan_result)

