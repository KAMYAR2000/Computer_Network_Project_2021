import optparse
import os
import re
import select
import socket
import struct
import sys

REQUEST = 1
REPLY= 2

class ARP:
    def __init__(self, value=None):
        self.eth_dest = struct.pack('6B', 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF)
        self.eth_src = None
        self._type_frame = struct.pack('H', socket.htons(0x0806))
        self._type_hrd = struct.pack('H', socket.htons(1))

        self._type_pro = struct.pack('H', socket.htons(0x0800))
        self._mac_len = struct.pack('B', struct.calcsize('6B'))
        self._op = struct.pack('H', socket.htons(REQUEST))

        self.mac_sender = None
        self.ip_sender = None
        self.mac_receiver = struct.pack('6B', 0x00, 0x00, 0x00, 0x00, 0x00, 0x00)
        self.ip_receiver = socket.inet_aton(value)

        self.set_mac()
        self.set_ip()
        self._ip_len = struct.pack('B', len(self.ip_sender))

    def set_mac(self):
        mac_ = ''
        for l in re.split(r':', MAC):
            mac_ += chr(int('0x' + l, 16))
        self.eth_src = mac_
        self.mac_sedr = mac_

    def set_ip(self):
        self.ip_sender = socket.inet_aton(IP)

    def to_string(self):
        return self.eth_dest + self.eth_src + self._type_frame + self._type_hrd + self._type_pro + self._mac_len + \
               self._ip_len + self._op + self.mac_sender + self.ip_sender + self.mac_receiver + self.ip_receiver


class Address:
    def __init__(self):
        self.sections_first = []
        self.sections_last = []
        return

    def IPRange(self, ip_first, ip_last):
        for s in re.split('\.', ip_first):
            self.sections_first.append(int(s))

        for sec in re.split('\.', ip_last):
            self.sections_last.append(int(sec))

    def iteration(self):           #Reach Next IP
        self.sections_first[3] += 1

        if self.sections_first[3] == 256:
            self.sections_first[3] = 0
            self.sections_first[2] += 1

        if self.sections_first[2] == 256:
            self.sections_first[2] = 0
            self.sections_first[1] += 1

        if self.sections_first[1] == 256:
            self.sections_first[1] = 0
            self.sections_first[0] += 1

        if self.sections_first[0] == 256:
            return False

        if self.sections_first == self.sections_last:
            return False

        return True

    def printing(self):
        arr = []
        for i in self.sections_first:
            arr.append(str(i))
        return '.'.join(arr)


def ARP_operation():
    ip_address = Address()
    ip_address.IPRange(sys.argv[1], sys.argv[2])
    sock = socket.socket(socket.PF_PACKET, socket.SOCK_RAW)
    sock.bind((nic, 0x0806))
    while ip_address.iteration():
        print(str(ip_address))
        packet = ARP(ip_address.__str__())
        sock.send(packet.to_string())
        receive = select.select([sock], [], [], TIMEOUT)
        if receive[0]:  # data
            data = sock.recv(42)
            if ord(data[21]) == REPLY:
                print(ip_address)
            else:
                print('error occurred on packet')


def check_errors():
    try:
        socket.inet_aton(sys.argv[1])   #converts an IPv4 address from the dotted-quad string format to 32-bit packed binary format
    except socket.error:
        parser.error("error occurred in net address")

    try:
        socket.inet_aton(sys.argv[2])
    except socket.error:
        parser.error("error occurred in net mask")

    nic = sys.argv[3]
    if not re.match(r'^eth\d{1}$', nic):
        parser.error("error occurred in net interface")

    ifconfig = os.popen('ifconfig ' + nic).read()

    m = re.search(r'HWaddr\s([a-f\d:]+)', ifconfig)
    if m:
        MAC = m.group(1)

    m = re.search(r'inet\saddr:([\d\.]+)\s', ifconfig)
    if m:
        IP = m.group(1)

    return MAC, IP


if __name__ == '__main__':
    parser = optparse.OptionParser(usage='usage: %prog net_address_first net_address_last nic Timeout')
    args = parser.parse_args()
    nic = sys.argv[3]
    TIMEOUT = sys.argv[4]
    MAC, IP = check_errors()
    ARP_operation()