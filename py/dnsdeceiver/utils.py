#!/usr/bin/env python3

__author__ = 'foxtrot_charlie'
__licence__ = 'GPLv2'


import socket
import fcntl
import struct
import toml
import scapy.all
import ipaddress


class bcolors:
    HEADER = '\033[95m'
    OKBLUE = '\033[94m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'


def getHwAddr(ifname):
    """
    Utils function getting mac address of the specified interface using ioctl calls
    :param ifname: string - name of the interface
    :return: string containing MAC address
    :raise: OSError - no such device
    """
    try:
        ifname = ifname.encode('utf-8')
    except AttributeError:
        pass
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    info = fcntl.ioctl(s.fileno(), 0x8927,  struct.pack('256s', ifname[:15]))
    return ''.join(['%02x:' % char  for char in info[18:24]])[:-1]


def chngHwAddr(ifname):
    """
    Utils function changing mac addres of the specified interface using ioctl call
    :param ifname: string - interface name
    :return: None
    :raise: OSError - no such device
    """
    raise NotImplementedError


def arpping(ip):
    """
    Uitls function obtaining MAC address of host with given IP address
    :param ip: string - ip address of target host
    :return: string - mac address of target host
    """
    ans, unans = scapy.all.arping(ip, verbose=0)
    for s,r in ans:
        return r[scapy.all.Ether].src


def get_hosts(ip):
    """
    Utils function calculating all hosts addresses in the specified network
    :param ip: IP addr with subnet ip/sub notation
    :return: list of hosts (strings) in the network
    """
    hosts = []
    net = ipaddress.IPv4Network(ip)
    for h in list(net.hosts()):
        # print(h)
        hosts.append(str(h))

    return hosts


class ConfigParser():
    @staticmethod
    def load_config(fn):
        """
        Utils function loading TOML config file and returning dictionary
        :param fn:
        :return:
        """
        toml_file = None
        conf = {}
        with open(fn, 'r') as f:
            toml_file = toml.loads(f.read())


        return toml_file


if __name__ == '__main__':
    print(getHwAddr('wlp3s0'))
    print(getHwAddr('enp0s31f6'))
    print(arpping('192.168.0.1'))
    print(arpping('192.168.0.19'))
    conf = ConfigParser().load_config("config.toml")
    print(conf)
    hosts = get_hosts("192.168.0.0/24")
    #print(hosts)
    # print(getHwAddr('eth0'))
