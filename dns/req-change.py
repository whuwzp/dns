
#!/usr/bin/env python
# coding=utf-8
#!/usr/bin/env python
import dns.resolver
import time
import xlrd
from xlwt import *   
import os  
import threading 

def req():
	
	global id
	

	domain = 'www.example.com'
	delay = []
	for i in range(100):
	    # domain = raw_input('Please input an domain: ')
	    t1 = time.time()
	    print t1   
	    A = dns.resolver.query(domain, 'A')  
	    t2 = time.time()
	    print t2 
	    print "query time is : "  ,t2 - t1 
	    delay.append(t2-t1)

	    if lock.acquire():
		id += 1
	    	table.write(id,0,id)
	    	table.write(id,1,t2-t1)  
		lock.release()
	    for i in A.response.answer:     
		for j in i.items:     
		    print j.to_text() 

 
lock = threading.Lock()
file = Workbook(encoding = 'utf-8')     
file_name = 'change-controller.exl'
id = 0
table = file.add_sheet(file_name)  
threads = []
for i in range(3):
	t = threading.Thread(target=req)
	threads.append(t)


if __name__ == '__main__':
    for t in threads:
        t.setDaemon(True)
        t.start()
    t.join()
    file.save(file_name)
         


