
#!/usr/bin/env python
# coding=utf-8
#!/usr/bin/env python
import dns.resolver
import time
import xlrd
from xlwt import *   
import os  

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
    for i in A.response.answer:     
        for j in i.items:     
            print j.to_text() 

 
file = Workbook(encoding = 'utf-8')     

file_name = 'three-controller.exl'

table = file.add_sheet(file_name)           

for i in range(len(delay)):
    table.write(i,0,i)
    table.write(i,1,delay[i])
file.save(file_name)

os.system('chmod -R 777 ../trans')
