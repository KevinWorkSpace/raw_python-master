import random
import select
# import module
import socket
import time

from raw_python import ICMPPacket, parse_icmp_header, parse_eth_header, parse_ip_header

ttl = 0
addr = None
curr_addr = None

def calc_rtt(time_sent):
    return time.time() - time_sent


def catch_ping_reply(s, ID, time_sent, timeout=1):
    # create while loop
    while True:
        starting_time = time.time()  # Record Starting Time

        # to handle timeout function of socket
        process = select.select([s], [], [], timeout)

        # check if timeout
        if not process[0]:
            s.setsockopt(socket.SOL_IP, socket.IP_TTL, ttl)
            # Request sent
            global addr
            global curr_addr

            ID = single_ping_request(s, addr)

            # receive packet
            try:
                s.settimeout(1)
                rec_packet, curr_addr = s.recvfrom(1024)

            except socket.error:
                return calc_rtt(time_sent), None, None
                # pass

            # extract icmp packet from received packet
            icmp = parse_icmp_header(rec_packet[20:28])

            return calc_rtt(time_sent), parse_ip_header(rec_packet[:20]), icmp
        else:
            # receive packet
            rec_packet, curr_addr = s.recvfrom(1024)
            # extract icmp packet from received packet
            icmp = parse_icmp_header(rec_packet[20:28])
            # check identification
            if icmp['id'] == ID:
                return calc_rtt(time_sent), parse_ip_header(rec_packet[:20]), icmp


def single_ping_request(s, addr=None):
    # Random Packet Id
    pkt_id = random.randrange(10000, 65000)

    # Create ICMP Packet
    packet = ICMPPacket(_id=pkt_id).raw

    # Send ICMP Packet
    while packet:
        # print(type(addr))
        if(type(addr) is tuple):
            sent = s.sendto(packet, (addr[0], 1))
        else:
            sent = s.sendto(packet, (addr, 1))
        packet = packet[sent:]

    return pkt_id


def main():
    # create socket
    s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)

    # take Input
    global addr
    global curr_addr
    addr = input("[+] Enter Domain Name : ") or "www.sustc.edu.cn"
    curr_addr = addr
    print('PING {0} ({1}) 56(84) bytes of data.'.format(addr, socket.gethostbyname(addr)))
    global ttl
    ttl = 1
    while True:
        s.setsockopt(socket.SOL_IP, socket.IP_TTL, ttl)
        # Request sent
        ID = single_ping_request(s, addr)

        # Catch Reply
        rtt, reply, icmp_reply = catch_ping_reply(s, ID, time.time())

        if reply:
            reply['length'] = reply['Total Length'] - 20  # sub header
            print(ttl, ' {0[length]} bytes reply from {0[Source Address]} ({0[Source Address]}): '
                  'icmp_seq={1[seq]} ttl={0[TTL]} time={2:.2f} ms'
                  .format(reply, icmp_reply, rtt*1000))
            if reply['Source Address'] == socket.gethostbyname(addr):
                break
        else:
            print('{:<4} *'.format(ttl))
        ttl += 1
        if ttl > 30:
            break


if __name__ == '__main__':
    main()