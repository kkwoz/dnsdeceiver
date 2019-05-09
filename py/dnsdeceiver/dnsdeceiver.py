#!/usr/bin/env python3

__author__ = 'foxtrot_charlie'
__licence__ = 'GPLv2'

import logging
import cmd
import sys
import queue
import threading
import argparse

import arpspoofer
import dnsspoofer
import utils

logger = logging.getLogger("DNSDECEIVER")
logger.setLevel(logging.DEBUG)
fh = logging.StreamHandler()
formatter = logging.Formatter("%(name)s; %(asctime)s; %(levelname)s; %(message)s", "%Y-%m-%d %H:%M:%S")
fh.setFormatter(formatter)
logger.addHandler(fh)

logo = utils.bcolors.OKBLUE + \
       r'''
        ____  _  _  ___    ____  ____  ___  ____  ____  _  _  ____  ____ 
       (  _ \( \( )/ __)  (  _ \( ___)/ __)( ___)(_  _)( \/ )( ___)(  _ \
        )(_) ))  ( \__ \   )(_) ))__)( (__  )__)  _)(_  \  /  )__)  )   /
       (____/(_)\_)(___/  (____/(____)\___)(____)(____)  \/  (____)(_)\_)
                                                       by foxtrot_charlie
       ''' + utils.bcolors.ENDC


class DNSDeceiver_shell(cmd.Cmd):
    intro = utils.bcolors.OKBLUE + \
            '\n\n Welcome to the DNSDeceiver shell! Type help or ? to list commands.\n' + \
            utils.bcolors.ENDC

    prompt = utils.bcolors.FAIL + '>' + utils.bcolors.ENDC

    def __init__(self, args, config={}):
        super(DNSDeceiver_shell, self).__init__()

        self.dns_queue = queue.Queue()
        self.arp_queue = queue.Queue()
        self.quit_event = threading.Event()

        logger.info('Reading config...')
        self.config = utils.ConfigParser.load_config(args.config) if args.config is not None else config

        if 'arp' not in self.config.keys():
            self.config['arp'] = {}
        if 'dns' not in self.config.keys():
            self.config['dns'] = {}

        logger.info('Initializing ARPspoofer...')
        self.arpspoofer = arpspoofer.ARPspoofer(event=self.quit_event, queue=self.arp_queue, config=self.config['arp'])
        logger.info('Initialization of ARPspoofer completed!')

        logger.info('Initializing DNSspoofer...')
        self.dnsspoofer = dnsspoofer.DNSSpoofer(event=self.quit_event, queue=self.arp_queue, config=self.config['dns'])
        logger.info('Initialization of DNSspoofer completed!')

        logger.info('Running ARPspoofer...')
        self.arpspoofer.start()

        logger.info('Running DNSspoofer...')
        self.dnsspoofer.start()

        logger.info('Running normal console now, use wisely!')

    def __send_to_arpspoofer(self, cmd):
        """
        Helper function for communication with ARPspoofer module via named queue
        :param cmd: list - command to be sent to ARPspoofer
        :return: None
        """
        self.arp_queue.put(cmd)

    def __send_to_dnsspoofer(self, cmd):
        """
        Helper function for communication with DNSspoofer module via named queue
        :param cmd: list - command to be sent DNSspoofer
        :return: None
        """
        self.dns_queue.put(cmd)

    def do_add_dns(self, args):
        """Add DNS entry to be spoofed"""
        _CMD_ = "a"
        args = self.__parse(args)
        args = (_CMD_,) + args
        self.__send_to_dnsspoofer(args)

    def do_rm_dns(self, args):
        """Remove DNS entry spoofing"""
        _CMD_ = "d"
        """Add DNS entry to be spoofed"""
        _CMD_ = "a"
        args = self.__parse(*args)
        args = (_CMD_,) + args
        self.__send_to_dnsspoofer(args)

    def do_rd(self, args):
        """Add DNS entry to be spoofed"""
        self.do_rm_dns(args)

    def do_ad(self, args):
        """Remove DNS entry spoofing"""
        self.do_add_dns(args)

    def do_list_dns(self, args):
        """Show list of dns targets to spoof"""
        _CMD_ = "ls"
        args = self.__parse(args)
        args = (_CMD_,) + args
        self.__send_to_dnsspoofer(args)
        while not self.dns_queue.empty():
            c = self.dns_queue.get()
            if c[0] == "lsa":  # check if ls answer
                print(utils.bcolors.OKGREEN + "TARGETS:")
                for i in c[1:]:
                    print(i)
                print(utils.bcolors.ENDC)
                break
            else:
                self.dns_queue.put(c)
                continue

    def do_ld(self, args):
        """Show list of dns targets to spoof"""
        self.do_list_dns(args)

    def do_list_arp(self, args):
        """Show list of arp spoofing targets"""
        _CMD_ = "ls"
        args = self.__parse(args)
        args = (_CMD_,) + args
        self.__send_to_arpspoofer(args)
        while not self.arp_queue.empty():
            c = self.arp_queue.get()
            if c[0] == "lsa":  # check if ls answer
                print(utils.bcolors.OKGREEN + "TARGETS:")
                for i in c[1:]:
                    print(i)
                print(utils.bcolors.ENDC)
                break
            else:
                self.arp_queue.put(c)
                continue

    def do_stop_arp_poisoning(self, args):
        """Stop ARP poisoning"""
        pass

    def do_start_arp_poisoning(self, args):
        """Start ARP poisoning"""
        pass

    def do_start_dns_spoofing(self, args):
        """Start spoofing dns"""
        pass

    def do_stop_dns_spoofing(self, args):
        """Stop spoofing dsn"""
        pass

    def do_quit(self, args):
        """Gracefully shutdown utility: quit"""
        self.do_close(args)

    def do_q(self, args):
        """Gracefully shutdown utility: q"""
        self.do_close(args)

    def do_exit(self, args):
        """Gracefully shutdown utility: exit"""
        self.do_close(args)

    def do_list_threads(self, args):
        """List all active threads (for debug only)"""
        for i in threading.enumerate():
            print(i)

    def do_close(self, args=None):
        """Gracefully shutdown utility: close"""
        logger.critical('Exiting...')
        logger.info('Signaling the end of DNSspoofer execution...')
        logger.info('Signaling the end of ARPspoofer execution...')
        self.quit_event.set()
        logger.info('Waiting for threads to stop...')
        try:
            self.dnsspoofer.join()
        except RuntimeError:
            pass
        logger.info("DNSspoofer joined!")
        try:
            self.arpspoofer.join()
        except RuntimeError:
            pass
        logger.info("ARPspoofer joined!")
        sys.exit(-1)

    def __parse(self, arg):
        'Convert a series of zero or more numbers to an argument tuple'
        return tuple(map(int, arg.split()))


if __name__ == '__main__':
    print(logo)
    ap = argparse.ArgumentParser(
        description='Small tool to spoof/edit DNS responses using ARP spoofing.',
        epilog='Handle with care!'
    )
    ap.add_argument('-f', '--config', help="config TOML file", default=None, metavar="config.toml")
    ap.add_argument('-d', '--dns', help="List of DNS queries (comma-separated) to be spoofed (addr:spoofed pairs)",
                    default=None, nargs="*", metavar="site.pl:evil_site.pl")
    ap.add_argument(
        '-a', '--arp',
        help="List of IP addresses (comma-separated) to be attacked via ARP spoofing (0.0.0.0 for whole network)",
        default="0.0.0.0", nargs='*', metavar="IP"
    )

    args = ap.parse_args()
    logger.debug('{}'.format(args))
    dd = DNSDeceiver_shell(args)
    try:
       dd.cmdloop()
    except KeyboardInterrupt:
        pass
