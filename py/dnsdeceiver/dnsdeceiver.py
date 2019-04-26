#!/usr/bin/env python3

__author__ = 'foxtrot_charlie'
__licence__ = 'GPLv2'


import sys
import os
import threading
import logging
import cmd


logger = logging.getLogger("ARPSPOOFER")
logger.setLevel(logging.DEBUG)
fh = logging.StreamHandler()
formatter = logging.Formatter("%(name)s; %(asctime)s; %(levelname)s; %(message)s", "%Y-%m-%d %H:%M:%S")
fh.setFormatter(formatter)
logger.addHandler(fh)

logo = r'''
 ____  _  _  ___    ____  ____  ___  ____  ____  _  _  ____  ____ 
(  _ \( \( )/ __)  (  _ \( ___)/ __)( ___)(_  _)( \/ )( ___)(  _ \
 )(_) ))  ( \__ \   )(_) ))__)( (__  )__)  _)(_  \  /  )__)  )   /
(____/(_)\_)(___/  (____/(____)\___)(____)(____)  \/  (____)(_)\_)
'''

class DNSDeceiver_shell(cmd.Cmd):
    intro = '{} \n\n Welcome to the DNSDeceiver shell! Type help or ? to list commands.\n'.format(logo)
    prompt = '>'

    def __init__(self):
        super(DNSDeceiver_shell, self).__init__()

    def do_add_dns(self, args):
        """Add DNS entry to be spoofed"""
        pass

    def do_rm_dns(self, args):
        """Remove DNS entry spoofing"""
        pass

    def do_rd(self, args):
        """Add DNS entry to be spoofed"""
        self.do_rm_dns(args)

    def do_ad(self, args):
        """Remove DNS entry spoofing"""
        self.do_add_dns(args)

    def do_list_dns(self, args):
        """Show list of dns targets to spoof"""
        pass

    def do_ld(self, args):
        """Show list of dns targets to spoof"""

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

    def do_close(self, args):
        """Gracefully shutdown utility: close"""
        return True



if __name__ == '__main__':
    dd = DNSDeceiver_shell()
    dd.cmdloop()