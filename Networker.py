#!/usr/bin/env python3
from scapy.all import *
import sys
from colorama import init, Fore, Back, Style


# Colorama globals settings
init()
missing = Style.RESET_ALL + Fore.RED + Style.DIM
error = Style.RESET_ALL + Back.RED + Fore.BLACK
result = Style.RESET_ALL + Back.GREEN + Fore.BLACK
info = Style.RESET_ALL + Fore.CYAN


class Networker:
    """
        Networker class with modules for various networking jobs
         1. scanner(ip_address, port)
         2. networkScanner(gateway_ip)
         3. ping(ip_address)
         4. portScanner(ip_address, port)
         5. commonPortsScanner(ip_address)
         6. allPortsScanner(ip_address)
         7. webscan(URL)
    """

    def __init__(self):
        pass

    def scanner(self, ip_addr, port):
        """
            scanner(ip_address, port)
            Simply Scans whatever is passed and returns a TCP scan reply
            ip_address can be an IP address or URL
            port must be an integer
        """
        tcp = IP(dst=ip_addr) / TCP(dport=port)
        res = sr1(tcp, timeout=5, verbose=False)
        return res

    def networkScanner(self, gateway_ip):
        """
            networkScanner(gateway_ip)
            Scans for all the systems on a network for a particular gateway
            gateway_ip can be the actual gateway IP or any node on the gateway's network
        """
        if self.ping(gateway_ip):
            ip_seg = gateway_ip.split(".")
            ip_seq = ".".join(ip_seg[0:3])
            for machine_id in range(1, 256):
                self.ping(f"{ip_seq}.{machine_id}")

    def ping(self, ip_addr):
        """
            ping(ip_address)
            ICMP pings an IP for the status of connectivity
            ip_address can be an IP address or URL
        """
        icmp = IP(dst=ip_addr) / ICMP()
        res = sr1(icmp, timeout=2, verbose=False)
        if str(type(res)) == "<class 'NoneType'>":
            print(
                f"{missing} system with ip `{ip_addr}` is either down or doesn't exist"
            )
            return False
        else:
            print(f"{result}: system with ip {res.src} is live")
            return True

    def portScanner(self, ip_addr, port):
        """
            portScanner(ip_address, port)
            Scans the ip_address for the status of the port passed
            ip_address can be an IP address or URL
            port must be an integer
        """
        try:
            res = self.scanner(ip_addr, port)
            if str(type(res)) == "<class 'NoneType'>":
                print(f"{missing} port {port} closed on {ip_addr}", end="")
                return False
            else:
                if res.sprintf("%TCP.flags%") == "SA":
                    print(f"{result}: port {res.sport} is open on {ip_addr} :", end="")
                    return True
                else:
                    print(f"{missing}: port {port} closed on {ip_addr} :", end="")
                    return False

        except socket.gaierror:
            print(f"{error} {ip_addr} Name or service not known")
            sys.exit()

    def commonPortsScanner(self, ip_addr):
        """
            commonPortsScanner(ip_address)
            Scans the ip_address for the status of few common ports
            ip_address can be an IP address or URL
        """
        ports = {
            21: "FTP",
            22: "SSH",
            25: "SMTP",
            53: "DNS",
            80: "HTTP",
            110: "POP3",
            123: "NTP",
            143: "IMAP",
            443: "HTTPS",
            445: "Microsoft-ds",
            465: "SMTPS",
            631: "CUPS",
            993: "IMAPS",
            995: "POP3",
        }

        for port in ports.keys():
            print(f"{info} {ports[port]} scanning: ", end="")
            self.portScanner(ip_addr, port)
            print()

    def allPortsScanner(self, ip_addr):
        """
            allPortsScanner(ip_address)
            Scans the ip_address for the status of all possible ports
            ip_address can be an IP address or URL
        """
        for port in range(1, 65536):
            print(f"{info} {port} scanning: ", end="")
            self.portScanner(ip_addr, port)
            print()

    def webscan(self, URL):
        """
            webscan(URL)
            Scans the URL for the status of common web hosting/service ports [80(http), 443(https), 8080(dev)]
            ip_address can be an IP address or URL
            port must be an integer
        """
        for port in [80, 443, 8080]:
            if self.portScanner(URL, port):
                print(f"{result} Website {URL} active")
                return
        print(
            f"{info} No website running on general hosting ports\nYou may run a full scan for affirmation"
        )


if __name__ == "__main__":
    work = Networker()
    # work.networkScanner('192.168.1.1')
