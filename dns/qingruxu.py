# coding:utf-8
import socket
import struct

# dns 服务器地址
ip = '127.0.0.1'
port = 53
# 创建一个dup通讯
sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
# rfc1035
# format
# +---------------------+
# |        Header       |
# +---------------------+
# |       Question      | the question for the name server
# +---------------------+
# |        Answer       | RRs answering the question
# +---------------------+
# |      Authority      | RRs pointing toward an authority
# +---------------------+
# |      Additional     | RRs holding additional information
# +---------------------+
#
# header
#                                 1  1  1  1  1  1
#   0  1  2  3  4  5  6  7  8  9  0  1  2  3  4  5
# +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
# |                      ID                       |
# +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
# |QR|   Opcode  |AA|TC|RD|RA|   Z    |   RCODE   |
# +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
# |                    QDCOUNT                    |
# +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
# |                    ANCOUNT                    |
# +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
# |                    NSCOUNT                    |
# +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
# |                    ARCOUNT                    |
# +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
request_id = 65535
# 2个Byte 长度无符号数
header = struct.pack('!HBBHHHH', request_id, 1, 0, 1, 0, 0, 0)
# question = struct.pack("!B5sB3sBHH",5,"baidu",3,"com",0,1,1)  #这里是原生格式 就是数一下有几个字母
# 格式要求是5baidu3com011 最后的11是2个字节的宽度
# QTYPE 1 是 A记录
# QCLASS 默认都是1
question = ""
domain = "www.whuwzp.cn"
# 用算法实现上面的格式
for element in domain.split("."):
    question += struct.pack("!B", len(element)) + element
question += struct.pack("!BHH", 0, 1, 1)

dns_req = header + question
sock.sendto(dns_req, (ip, port))
resp_data, (resp_addr, resp_port) = sock.recvfrom(512)
# Resource record format
#   0  1  2  3  4  5  6  7  8  9  0  1  2  3  4  5
# +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
# |                                               |
# /                                               /
# /                      NAME                     /
# |                                               |
# +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
# |                      TYPE                     |
# +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
# |                     CLASS                     |
# +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
# |                      TTL                      |
# |                                               |
# +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
# |                   RDLENGTH                    |
# +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--|
# /                     RDATA                     /
# /                                               /
# +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+

# header
(resp_request_id, resp_flag, resp_qdcount, resp_ancount, resp_nscount, resp_arcount) = struct.unpack("!HHHHHH",
                                                                                                     resp_data[:12])
print len(question)
# 检测request_id 和 RQ RCODE
if resp_request_id == request_id:
    # RQ 是15位
    if resp_flag == resp_flag | 1 << 15:
        # RCODE 必须是0 这里与上 0 和原来的值做比较
        if resp_flag == resp_flag & ~0xf:
            # 返回记录数大于0 查询记录数大于0
            if 0 < resp_qdcount and 0 < resp_ancount:
                # 减去header 6个字节
                record = resp_data[12:]
                # 减去问题 返回问题和发送问题一样
                record = record[len(question):]
                (offset, type, rdclass, ttl, rdlen, ip1, ip2, ip3, ip4) = struct.unpack("!HHHLHBBBB", record[
                                                                                                      :struct.calcsize(
                                                                                                          "!HHHLHBBBB")])
                print "{0}.{1}.{2}.{3}".format(ip1, ip2, ip3, ip4)

