#!/usr/bin/env python3
import os
import sys


def main():
    try:
        user_input = input("Do you want to unblock an IP address? (y/n): ").strip().lower()
        if user_input == 'y':
            ip_to_unblock = input("Enter the IP address to unblock: ")
            UnblockIT(ip_to_unblock)
        else:
            print("Bye")

    except KeyboardInterrupt:
        sys.exit("bye")


def UnblockIT(ipaddr):
    os.popen("iptables -D INPUT -s {} -j DROP".format(ipaddr))


if __name__=="__main__":
    main()