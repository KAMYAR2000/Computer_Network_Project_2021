import argparse
import socket
import struct
import random
import time
import select
import math
import sys

ICMP_ECHO = 8
ICMP_CODE = socket.getprotobyname('icmp')
ICMP_MAX_RECV = 2048

def create_packet(id, packet_size):
    header = struct.pack('bbHHh', ICMP_ECHO, 0, 0, id, 1)
    data = ''
    padBytes = []
    startVal = 0x42
    for i in range(startVal, startVal + packet_size):
        padBytes += [(i & 0xff)]
    data = bytes(padBytes)

    my_checksum = checksum(header + data)
    header = struct.pack('bbHHh', ICMP_ECHO, 0,
                         socket.htons(my_checksum), id, 1)
    return header + data

def checksum(source_string):
    countTo = (int(len(source_string) / 2)) * 2
    sum = 0
    count = 0
    loByte = 0
    hiByte = 0
    while count < countTo:
        if (sys.byteorder == "little"):
            loByte = source_string[count]
            hiByte = source_string[count + 1]
        else:
            loByte = source_string[count + 1]
            hiByte = source_string[count]
        sum = sum + (hiByte * 256 + loByte)
        count += 2

    if countTo < len(source_string):
        loByte = source_string[len(source_string) - 1]
        sum += loByte

    sum &= 0xffffffff
    sum = (sum >> 16) + (sum & 0xffff)
    sum += (sum >> 16)
    answer = ~sum & 0xffff
    answer = socket.htons(answer)
    return answer

def do_one(host, ttl, timeout, packet_size):
    my_socket = socket.socket(socket.AF_INET, socket.SOCK_RAW, ICMP_CODE)
    my_socket.setsockopt(socket.SOL_IP, socket.IP_TTL, ttl)
    packet_id = send_one_ping(my_socket,host, packet_size)
    ping_res = receive_one_ping(my_socket, packet_id, time.time(), timeout)
    my_socket.close()
    return ping_res

def send_one_ping(mySocket, host, packet_size):
    packet_id = int(random.random() * 65535)
    packet = create_packet(packet_id, packet_size)
    while packet:
        sent = mySocket.sendto(packet, (host, 1))
        packet = packet[sent:]
    return packet_id

def receive_one_ping(my_socket, packet_id, time_sent, timeout):
    time_left = timeout
    while True:
        started_select = time.time()
        ready = select.select([my_socket], [], [], time_left)
        how_long_in_select = time.time() - started_select
        if ready[0] == []:
            return 0
        time_received = time.time()
        rec_packet, addr = my_socket.recvfrom(ICMP_MAX_RECV)
        icmp_header = rec_packet[-8:]
        type, code, checksum, p_id, sequence = struct.unpack(
            'bbHHh', icmp_header)
        if p_id == packet_id:
            total_time_ms = (time_received - time_sent) * 1000
            total_time_ms = math.ceil(total_time_ms * 1000) / 1000
            return (addr[0], total_time_ms)
        time_left -= time_received - time_sent
        if time_left <= 0:
            return 0

def total(host, ttl, timeout, max_tries, packet_size):
    tries = []
    trystr = []
    for i in range (0 , max_tries):
        tries.append(do_one(host, ttl, timeout, packet_size))

    for i in range(0, max_tries ):
        if tries[i] == 0:
            trystr.append('*')
        else:
            try:
                data = socket.gethostbyaddr(tries[i][0])
                name = repr(data[0])
                trystr.append(tries[i][0] + '->' + name + '-' + str(tries[i][1]) + 'ms')
            except Exception:
                trystr.append(tries[i][0] + '-' + str(tries[i][1]) + 'ms')

    final_string = ""
    for i in range(0, max_tries):
        final_string = final_string + trystr[i] + ', '

    final_string = str(ttl) + '  ' + final_string

    if tries[0] == 0:
        destination_reached = False
    else:
        destination_reached = tries[0][0] == host

    return (final_string, destination_reached)

def create_parser():
    parser = argparse.ArgumentParser()
    parser.add_argument('destination_server')
    parser.add_argument('-c', '--count', required=False, default=3, type=int, metavar='Count of packets')
    parser.add_argument('-t', '--timeout', required=False, default=1, type=int, metavar='Timeout in ms')
    parser.add_argument('-m', '--maxhops', required=False, default=30, type=int, metavar='Max hops')
    parser.add_argument('-i', '--initialTTL', required=False, default=1, type=int, metavar='initial TTL')
    parser.add_argument('-p', '--packet_size', required=False, default=55, type=int, metavar='Packet size in bytes')
    return parser

def ready(destination_server, max_tries = 3, packet_size = 55, max_ttl = 30, initial_ttl= 1, timeout = 1):
    host_ = socket.gethostbyname(destination_server)
    print('myTraceRoute to ' + destination_server + ' (' + host_ + '), ' + str(max_ttl) +
          ' maximum TTL.')

    try:
        for i in range(initial_ttl, max_ttl + 1):
            (line, destination_reached) = total(host_, i, timeout, max_tries, packet_size)
            print(line)
            if destination_reached:
                break
    except Exception as err:
        print(err)
    except KeyboardInterrupt as err:
        print(err)

if __name__ == '__main__':
    parser = create_parser()
    args = parser.parse_args(sys.argv[1:])
    destination_server = args.destination_server
    timeout = args.timeout
    packet_size = args.packet_size
    max_tries = args.count
    max_hops = args.maxhops
    initial_TTL = args.initialTTL
    ready(destination_server, max_tries, packet_size, max_hops, initial_TTL, timeout)