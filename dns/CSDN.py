#-*-coding:utf-8-*-
import socket
def ana_head(q,n):
    list1 = []
    print u'包长度%d'%len(q)
    print u'标识为：%x%x'%(ord(q[0]),ord(q[1]))
    print u'报文参数为：%x%x'%(ord(q[2]),ord(q[3]))
    print u'问题数：%x%x'%(ord(q[4]),ord(q[5]))
    print u'应答数：%x%x'%(ord(q[6]),ord(q[7]))
    print u'授权机构数：%x%x'%(ord(q[8]),ord(q[9]))
    print u'附加信息数：%x%x'%(ord(q[10]),ord(q[11]))
    for i in range(n+1):
        nu = 12+i
        list1.append('%d'%ord(q[nu]))
    str1 = ''.join(list1)
    print u'查询信息为：%s'%str1
    print u'查询类型为：%x%x'%(ord(q[n+13]),ord(q[n+14]))
    print u'查询类为：%x%x'%(ord(q[n+15]),ord(q[n+16]))
def ana_fin(c,x):
    times = ord(c[7])
    g = x+16
    for i in range(times):
        print '*******************************************************'
        print u'指针：%x%x'%(ord(c[g+1]),ord(c[g+2]))
        print u'第%d个资源的响应类型：%x%x'%(i+1,ord(c[g+3]),ord(c[g+4]))
        print u'第%d个资源的响应类：%x%x'%(i+1,ord(c[g+5]),ord(c[g+6]))
        print u'第%d个资源的生存时间：%d%d%d%d秒'%(i+1,ord(c[g+7]),ord(c[g+8]),ord(c[g+9]),ord(c[g+10]))
        print u'第%d个资源的数据长度：%x%x'%(i+1,ord(c[g+11]),ord(c[g+12]))
        print u'返回的IP地址：%d.%d.%d.%d'%(ord(c[g+13]),ord(c[g+14]),ord(c[g+15]),ord(c[g+16]))
        g+=16
    print '-----------------------------------------------------'
class dns():
    def _init_(self):
        pass
    def coding(self,second,first,root):
        len_root = '%s'%chr(len(root))
        l_root = len(root)
        len_first = '%s'%chr(len(first))
        l_first = len(first)
        if second:
            len_second ='%s'%chr(len(second))
            l_second = len(second)
            self.num = l_root+l_first+l_second+3
            q = b'\x5c\x6d\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00%s%s%s%s%s%s\x00\x00\x01\x00\x01'%(len_second,second,len_first,first,len_root,root)
            return q
        else:
            q = b'\x5c\x6d\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00%s%s%s%s\x00\x00\x01\x00\x01'%(len_first,first,len_root,root)
            self.num = l_root+l_first+2
            return q
    def send(self,q):
        sock = socket.socket(socket.AF_INET,socket.SOCK_DGRAM)
        sock.sendto(q,('8.8.8.8',53))
        sock_recv = sock.recv(4096)
        return sock_recv
    def info(self,q):
        flag = '%x%x'%(ord(q[2]),ord(q[3]))
        if flag == '10':
            print '-----------------------------------------------------'
            print u'此为查询报文'
            ana_head(q,self.num)
        else:
            print '-----------------------------------------------------'
            print u'此为返回报文'
            ana_head(q,self.num)
            ana_fin(q,self.num)

d = dns()
q = d.coding("www","whuwzp","cn")
d.info(q)
recv = d.send(q)
d.info(recv)
