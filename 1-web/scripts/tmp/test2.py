import sys
import random
import requests
import time
import datetime
import timeit


url = 'http://qlink'

headers = {
        'Accept':'application/json, text/javascript, */*; q=0.01',
        'Accept-Encoding':'gzip, deflate',
        'Accept-Language':'es-419,es;q=0.8',
        'Connection':'keep-alive',
        'Content-Length':'365',
        'Content-Type':'application/x-www-form-urlencoded; charset=UTF-8',
        'Host':url.replace('http://', '').replace('https://', ''),
        'Origin':url,
        'Referer':url+'/',
        'User-Agent':'Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/58.0.3029.81 Safari/537.36',
        'X-Requested-With':'XMLHttpRequest'
}

data = {
        'msg':'{"data":"fA3xPEXWdVvMlZCTgN5KFg==","salt":"7cf84dd833235507","iv":"c1c673154a746978d0d8f98a56c8b19a","iter":100,"decom":"false"}',
        'imprint':'false',
        'captcha':'false',
        'randomHash':'1493571857073',
        'from':'web_app',
        'x_token':'4bc0f8180c07582c4d9981d5dc4b748eeaca9103ec9d3d474fe4c27b0f6fa103',
        'lang':'es',
        'replyIntent':'false',
        'n':'180'
}


# sess = requests.Session()

# r = sess.post(url + '/inject', headers=headers, data=data)
# print
# print "resultado:"
# #print r.text
# print r.headers
# print r.json()

#random.seed(1234)
#print random.randint(1, 50)

#random.seed(12345)
#print random.randint(1, 50)




# natmchugh/php_mt.py
# https://gist.github.com/natmchugh/769c530d30092c479ff7

def _int32(x):
    # Get the 32 least significant bits.
    return int(0xFFFFFFFF & x)

class MT19937:

    def __init__(self, seed):
        # Initialize the index to 0
        self.index = 624
        self.mt = [0] * 624
        self.mt[0] = seed  # Initialize the initial state to the seed
        for i in range(1, 624):
            self.mt[i] = _int32(
                1812433253 * (self.mt[i - 1] ^ self.mt[i - 1] >> 30) + i)

    def extract_number(self):
        if self.index >= 624:
            self.twist()

        y = self.mt[self.index]

        # Right shift by 11 bits
        y = y ^ y >> 11
        # Shift y left by 7 and take the bitwise and of 0x9D2C5680
        y = y ^ y << 7 & 0x9D2C5680
        # Shift y left by 15 and take the bitwise and of y and 0xEFC60000
        y = y ^ y << 15 & 0xEFC60000
        # Right shift by 18 bits
        y = y ^ y >> 18

        self.index += 1

        return y

    def twist(self):
        for i in range(0, 624):
            # print self.mt[i]
            # Get the most significant bit and add it to the less significant
            # bits of the next number
            z = self.mt[i]
            y = _int32((self.mt[i] & 0x80000000) +
                       (self.mt[(i + 1) % 624] & 0x7fffffff))
            self.mt[i] = self.mt[(i + 397) % 624] ^ y >> 1

            if (z & 1 == 1):
                self.mt[i] ^=  0x9908b0df

        self.index = 0

#mt =  MT19937(1)
#for j in range(0, 624):
#    print mt.extract_number() >> 1
 

 
 

#https://github.com/php/php-src/blob/c8aa6f3a9a3d2c114d0c5e0c9fdd0a465dbb54a5/ext/standard/php_mt_rand.h
PHP_MT_RAND_MAX = (1<<31) - 1

# n' = a + n(b-a+1)/(M+1)
# https://github.com/php/php-src/blob/c8aa6f3a9a3d2c114d0c5e0c9fdd0a465dbb54a5/ext/standard/php_rand.h

def php_mt_srand(seed):
    mt = MT19937(seed)
    return mt

def php_mt_rand(mt, min, max, t_max):
    tmp = mt.extract_number() >> 1
    ret = min + tmp * (max - min  + 1) / (t_max + 1)
    return ret

#print mt_srand_and_rand_php(1234, 1, 50, PHP_MT_RAND_MAX)
#print mt_srand_and_rand_php(12345, 1, 50, PHP_MT_RAND_MAX)
#print mt_srand_and_rand_php(123456, 1, 50, PHP_MT_RAND_MAX)

'''
equivalente:
<?php

mt_srand(1234);
echo mt_rand(1, 50)."\n";

mt_srand(12345);
echo mt_rand(1, 50)."\n";

mt_srand(123456);
echo mt_rand(1, 50)."\n";

?>

'''
#mt =  MT19937(1234)
#aa = mt.extract_number() >> 1
#print aa
#print (aa % 51) + 1

#mt =  MT19937(12345)
#aa = mt.extract_number() >> 1
#print aa
#print (aa % 51) + 1

# #start = timeit.timeit()
# start = datetime.datetime.now()
# for i in range(10):
    # for j in range(10):
        # mt_srand_and_rand_php(1234, 1, 50, PHP_MT_RAND_MAX)
    # end = datetime.datetime.now()
    # delta = end - start
    # print str(i) + ": " + str(delta.microseconds + (delta.seconds * 1000000))


chars = '0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ'
xxx = 'ZjixfYtjSG'

resp_header_dt = datetime.datetime.strptime('Mon, 01 May 2017 17:36:28 GMT', '%a, %d %b %Y %H:%M:%S GMT')
resp_header_ue = time.mktime(resp_header_dt.timetuple())
resp_header_ue = int(resp_header_ue)

js_ue = 1493591895111

ii = resp_header_ue + js_ue

max = 0
for i in xrange(-200000, 100000):
    mt = php_mt_srand(i+ii)
    for j in range(len(xxx)):
        xx = php_mt_rand(mt, 0, len(chars)-1, PHP_MT_RAND_MAX)
        if chars[xx] != xxx[j]:
            break
        if (j + 1 > max):
            max = j + 1
    if (i % 1000 == 0):
        print "i: " + str(i) + " - max: " + str(max)
        sys.stdout.flush()

    


