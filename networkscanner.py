#!/bin/sh/python

import scapy.all as scapy
import argparse

def arguments():
    parser = argparse.ArgumentParser()
    parser.add_argument("-t", "--target", dest= "target_ip", help="target ip range")
    args_value = parser.parse_args()
    return args_value

def scan(ip):

    arp_request = scapy.ARP(pdst=ip)
    broadcast = scapy.Ether(dst='ff:ff:ff:ff:ff:ff')
    broadcast_request = broadcast/arp_request
    answered = scapy.srp(broadcast_request, timeout=1, verbose=False)[0]
    clients_list = []
    for element in answered:
        clients_dict = {"ip":element[1].psrc , "mac":element[1].hwsrc}
        clients_list.append(clients_dict)
    return clients_list

def print_result(results_list):

    print("IP\t\t\tMAC ADDRESS\n------------------------------------------")
    for client in results_list:
        print(client["ip"] + '\t\t' + client["mac"])

arguments_value = arguments()
scan_result = scan(arguments_value.target_ip)
print_result(scan_result)

