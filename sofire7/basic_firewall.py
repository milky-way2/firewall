#!/usr/bin/env python3
from datetime import datetime
import socket, struct, os
from pyfiglet import Figlet
import threading
import time
import sys
flag=False

def main():
    #show banner of project
    global flag
    if  not flag:
        ShowBanner()
        flag=True
    #creating socket
    s = socket.socket(socket.PF_PACKET, socket.SOCK_RAW, 8)
    dict = {}
    if len(sys.argv) in (2,3):
        if sys.argv[1] == "-u" or sys.argv[1] == "--unblock":
            UnblockIT(sys.argv[2])
            sys.exit("bye")
        elif sys.argv[1] == "-h" or sys.argv == "--help":
            print("For help menu run with -h [--help]")
            print("To unblock any ip run with -u [--unblock] <ip>")
            print("To stop the firewall press <CTRL+C>")
        else:
            print("Wrong argument")
    while True:
        try:
            pkt = s.recvfrom(65536) #declaring the bufer size
            ip_header = pkt[0][14:34]
            ip_hdr = struct.unpack("!8sB3s4s4s", ip_header)
            IP = socket.inet_ntoa(ip_hdr[3])

            tcp_header = pkt[0][34:54]
            tcp_hdr = struct.unpack("!HH9ss6s", tcp_header)

            if IP == "127.0.0.1":
                pass
            elif IP in dict.keys():
                if tcp_hdr[1] not in dict[IP]:
                    dict[IP].append(tcp_hdr[1])
                if len(dict[IP]) == 5:
                    print("This {} address was blocked".format(IP))
                    BlockIT(IP)
                    UnblockIT(IP)  #will unblock the blocked ip after 5 sec
            else:
                dict[IP] = []
        except KeyboardInterrupt:
            sys.exit("\tBye")
            break
    


#blocking the ip after 3 ping packet received
def BlockIT(ipaddr):
    os.popen("iptables -A INPUT -s {} -j DROP".format(ipaddr))
    with open("blocked_ips.txt", "a") as file:
        file.write(ipaddr + "\n")
    print("Blocked IP address:", ipaddr)


 #unblocking the ip's after 5 sec delay   
def UnblockIT(ipaddr):
    time.sleep(5)
    blocked_ips = set()  # Create a set for blocked IPs
    # os.popen("iptables -D INPUT -s {} -j DROP".format(ipaddr))


        # Create a separate thread for unblocking the IP
    unblock_thread = threading.Thread(target=lambda: os.popen("iptables -D INPUT -s {} -j DROP".format(ipaddr)))
    unblock_thread.start()


    with open("blocked_ips.txt", "r") as file:
        blocked_ips = set(ip.strip() for ip in file.readlines())  # Read IPs into a set
        blocked_ips.discard(ipaddr)  # Remove the specific IP from the set
    with open("blocked_ips.txt", "w") as file:
        for ip in blocked_ips:
            file.write(ip + "\n")
    print("UnBlocked IP address:", ipaddr)


#project banner show
def ShowBanner():
    figlet = Figlet()
    figlet.setFont(font="banner3-D")
    print(figlet.renderText("SoFire7"))
    figlet.setFont(font="slant")
    print(figlet.renderText("by Soham"))
    fs=lambda: (print("Starting firewall",end=""), [print(".", end="",flush=True) or time.sleep(1) for _ in range(5)])
    fs()
    print("\nFirewall started")



if __name__=="__main__":
    #calling main
    main()