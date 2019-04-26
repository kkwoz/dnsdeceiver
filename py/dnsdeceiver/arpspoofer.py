#!/usr/bin/env python3

__author__ = 'foxtrot_charlie'
__licence__ = 'GPLv2'


import sys
import os
import threading
import logging
import queue
from scapy.all import *


from . import utils


logger = logging.getLogger("ARPSPOOFER")
logger.setLevel(logging.DEBUG)
fh = logging.StreamHandler()
formatter = logging.Formatter("%(name)s; %(asctime)s; %(levelname)s; %(message)s", "%Y-%m-%d %H:%M:%S")
fh.setFormatter(formatter)
logger.addHandler(fh)

DEFAULT_GATEWAY = '192.168.0.1'
CommandQueue = queue.Queue()


class ARPspoofer(threading.Thread):
    """
    ARPspoofer class is used to provide ARP spoofing capability
    ARPspoofer can work in two modes. One mode provides ability
    to spoof ARP responses only for a specific target. Another
    option is to spoof whole ARP traffic in the network.
    """
    def __init__(self, config={}):
        """"""
        self.kernel_ipv4fwd = None
        self.gw = None
        self.network = None
        self.delay = None
        self.interface = None
        self.ip_mac_hshmap = None
        logger.info("Initializing ARPspoofer...")
        if os.getuid():
            logger.error("Run me as root!")
            sys.exit(-1)

        logger.info("Loading config...")
        self.__config_load(config)

    def __config_load(self, config={}):
        """"""
        self.kernel_ipv4fwd = config.get('kernel_ip4_fwd', 1)
        if self.kernel_ipv4fwd:
            logger.warning("Used kernel ipv4 forwarding feature.")
            os.system("echo %s > /proc/sys/net/ipv4/ip_forward".format(self.kernel_ipv4fwd))
            logger.info("Kernel IPv4 forwarding enabled")

        else:
            logger.error("Not implemented!")
            raise NotImplementedError

        self.gw = config.get('gateway', None)
        if not self.gw:
            logger.critical("IP of gateway not specified! Using default one: {}".format(DEFAULT_GATEWAY))
            self.gw = DEFAULT_GATEWAY


    def __config_reload(self, config={}):
        """"""
        pass

    def __build_arp_pkt(self):
        """
        Function building ARP response
        :return: Scapy ARP packet
        """

    def __build_eth_frame(self):
        pass

    def __send_arp(self):
        pass

    def __main_loop(self):
        pass

    def __restore_network(self):
        pass

    def __del__(self):
        if self.kernel_ipv4fwd:
            self.kernel_ipv4fwd = 0
            os.system("echo %s > /proc/sys/net/ipv4/ip_forward".format(self.kernel_ipv4fwd))
            logger.info("Kernel IPv4 forwarding disabled")



if __name__ == '__main__':
    print("helo")
    AS = ARPspoofer()
    logger.critical('Quiting arpspoofer')