#!/usr/bin/env python
import dns.resolver
import time
domain = 'www.example.com'
delay = []
for i in range(10000):
    # domain = raw_input('Please input an domain: ')
    t1 = time.time()
    print t1   
    A = dns.resolver.query(domain, 'A')  
    t2 = time.time()
    print t2 
    print "query time is : "  ,t2 - t1 
    delay.append(t2-t1) 
    for i in A.response.answer:     
        for j in i.items:     
            print j.to_text() 
