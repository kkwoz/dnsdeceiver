#!/usr/bin/env python3

__author__ = 'foxtrot_charlie'
__licence__ = 'GPLv2'


import socket
import fcntl
import struct
import scapy.all


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


if __name__ == '__main__':
    print(getHwAddr('wlp3s0'))
    print(getHwAddr('enp0s31f6'))
    # print(getHwAddr('eth0'))
