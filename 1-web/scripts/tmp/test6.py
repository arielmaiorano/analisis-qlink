import sys
import random
import requests
import time
import datetime
import timeit
import php_rand


url = 'http://qlink'

headers = {
        'Accept':'application/json, text/javascript, */*; q=0.01',
        'Accept-Encoding':'gzip, deflate',
        'Accept-Language':'es-419,es;q=0.8',
        'Connection':'keep-alive',
        #'Content-Length':'365',
        'Content-Type':'application/x-www-form-urlencoded; charset=UTF-8',
        'Host':url.replace('http://', '').replace('https://', ''),
        'Origin':url,
        'Referer':url+'/',
        'User-Agent':'Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/58.0.3029.81 Safari/537.36',
        'X-Requested-With':'XMLHttpRequest'
}

data = {
        'trk':'2508054487'
}


sess = requests.Session()

for i in range(10):
    r = sess.post(url + '/gtrkstatus', headers=headers, data=data)
    print
    print "resultado:"
    #print r.text
    #print r.headers
    print r.json()
    print int(time.time())
    sys.stdout.flush()
    #time.sleep(1)



