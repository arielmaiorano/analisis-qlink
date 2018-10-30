# -*- coding: utf-8 -*-

# en base a https://github.com/douggard/XorShift128Plus
#
# adaptado para resolución con valores truncados por CryptoJS.lib.WordArray.random()
# ejemplo con entradas de salt e iv en qlink (js/public/application.js) para estimar
# (adivinar) valores posibles siguientes del generador...
#
# * sólo se tomó en cuenta ejemplo para chrome

import math
import struct
import random
from z3 import *

###############################################################################

# ejemplo capturado desde browser chrome
# alert(CryptoJS.lib.WordArray.random(8).toString()); // así genera qlink el salt que enviará al servidor
# alert(CryptoJS.lib.WordArray.random(32).toString().substr(0,32)); // así genera qlink el iv que enviará al servidor
salt_hex = 'f7f195a46835dd93'
iv_hex = 'f37e44f2afe372308cb09ca5c102323d'

# [sólo como ejemplo] siguientes 8 + 16 bytes de salida del generador
# alert(CryptoJS.lib.WordArray.random(8).toString()); // ejemplo de siguientes 8 bytes del generador
# alert(CryptoJS.lib.WordArray.random(32).toString().substr(0,32));  // ejemplo de siguientes 16 bytes del generador
sig_8b_hex = '544a197133f961c5'
sig_16b_hex = '24467b8acf7c8abc6751417f721d563c'

###############################################################################

print 'se estimarán valores siguientes considerando salida conocida: ' + salt_hex + ' ' + iv_hex

words = [0, 0, 0, 0, 0, 0]
for i in range(2):
    ii = i * 8
    words[i] = int(salt_hex[ii:ii+8] + '00000', 16) & 0xFFFFFFFFFFFFF
    #print words[i]
for i in range(4):
    ii = i * 8
    words[i + 2] = int(iv_hex[ii:ii+8] + '00000', 16) & 0xFFFFFFFFFFFFF
    #print words[i + 2]

###############################################################################

# xor_shift_128_plus algorithm
def xs128p(state0, state1):
    s1 = state0 & 0xFFFFFFFFFFFFFFFF
    s0 = state1 & 0xFFFFFFFFFFFFFFFF
    s1 ^= (s1 << 23) & 0xFFFFFFFFFFFFFFFF
    s1 ^= (s1 >> 17) & 0xFFFFFFFFFFFFFFFF
    s1 ^= s0 & 0xFFFFFFFFFFFFFFFF
    s1 ^= (s0 >> 26) & 0xFFFFFFFFFFFFFFFF 
    state0 = state1 & 0xFFFFFFFFFFFFFFFF
    state1 = s1 & 0xFFFFFFFFFFFFFFFF
    generated = (state0 + state1) & 0xFFFFFFFFFFFFFFFF

    return state0, state1, generated

# Symbolic execution of xs128p
def sym_xs128p(slvr, sym_state0, sym_state1, generated, browser):
    s1 = sym_state0 
    s0 = sym_state1 
    s1 ^= (s1 << 23)
    s1 ^= LShR(s1, 17)
    s1 ^= s0
    s1 ^= LShR(s0, 26) 
    sym_state0 = sym_state1
    sym_state1 = s1
    calc = (sym_state0 + sym_state1)
    
    condition = Bool('c%d' % int(generated * random.random()))
    if browser == 'chrome':
        #xxx
        #impl = Implies(condition, (calc & 0xFFFFFFFFFFFFF) == int(generated))
        impl = Implies(condition, (calc & 0xFFFFFFFF00000) == int(generated))
    elif browser == 'firefox' or browser == 'safari':
        # Firefox and Safari save an extra bit
        impl = Implies(condition, (calc & 0x1FFFFFFFFFFFFF) == int(generated))

    slvr.add(impl)
    return sym_state0, sym_state1, [condition]

def reverse17(val):
    return val ^ (val >> 17) ^ (val >> 34) ^ (val >> 51)

def reverse23(val):
    return (val ^ (val << 23) ^ (val << 46)) & 0xFFFFFFFFFFFFFFFF

def xs128p_backward(state0, state1):
    prev_state1 = state0
    prev_state0 = state1 ^ (state0 >> 26)
    prev_state0 = prev_state0 ^ state0
    prev_state0 = reverse17(prev_state0)
    prev_state0 = reverse23(prev_state0)
    generated = (prev_state0 + prev_state1) & 0xFFFFFFFFFFFFFFFF
    return prev_state0, prev_state1, generated


# Firefox nextDouble():
    # (rand_uint64 & ((1 << 53) - 1)) / (1 << 53)
# Chrome nextDouble():
    # ((rand_uint64 & ((1 << 52) - 1)) | 0x3FF0000000000000) - 1.0
# Safari weakRandom.get():
    # (rand_uint64 & ((1 << 53) - 1) * (1.0 / (1 << 53)))
def to_double(browser, out):
    if browser == 'chrome':
        double_bits = (out & 0xFFFFFFFFFFFFF) | 0x3FF0000000000000
        double = struct.unpack('d', struct.pack('<Q', double_bits))[0] - 1
    elif browser == 'firefox':
        double = float(out & 0x1FFFFFFFFFFFFF) / (0x1 << 53) 
    elif browser == 'safari':
        double = float(out & 0x1FFFFFFFFFFFFF) * (1.0 / (0x1 << 53))
    return double


def main():
    # Note: 
        # Safari tests have always turned up UNSAT
        # Wait for an update from Apple?
    # browser = 'safari'
    browser = 'chrome'
    # browser = 'firefox'
    print 'BROWSER: %s' % browser

    # In your browser's JavaScript console:
    # _ = []; for(var i=0; i<5; ++i) { _.push(Math.random()) } ; console.log(_)
    # Enter at least the 3 first random numbers you observed here:
    
    #xxx
    #dubs = [0.4752549301773037, 0.08162196013326506, 0.8333085432653353]
    dubs = words

    if browser == 'chrome':
       dubs = dubs[::-1]

    #xxx
    #print dubs
    print 'valores a utilizar: ' + str(dubs)
    print 'resolviendo...'
    sys.stdout.flush()
    
    # from the doubles, generate known piece of the original uint64 
    generated = []
    #xxx
    # for idx in xrange(3):
        # if browser == 'chrome':
            # recovered = struct.unpack('<Q', struct.pack('d', dubs[idx] + 1))[0] & 0xFFFFFFFFFFFFF 
        # elif browser == 'firefox':
            # recovered = dubs[idx] * (0x1 << 53) 
        # elif browser == 'safari':
            # recovered = dubs[idx] / (1.0 / (1 << 53))
        # generated.append(recovered)
    for idx in xrange(len(dubs)):
        generated.append(dubs[idx])
        
    # setup symbolic state for xorshift128+
    ostate0, ostate1 = BitVecs('ostate0 ostate1', 64)
    sym_state0 = ostate0
    sym_state1 = ostate1
    slvr = Solver()
    conditions = []

    # run symbolic xorshift128+ algorithm for three iterations
    # using the recovered numbers as constraints
    #xxx
    #for ea in xrange(3):
    for ea in xrange(len(dubs)):
        sym_state0, sym_state1, ret_conditions = sym_xs128p(slvr, sym_state0, sym_state1, generated[ea], browser)
        conditions += ret_conditions

    if slvr.check(conditions) == sat:
    
        #xxx
        print 'modelo resuelto: '
        print(slvr.model())
        print
        sys.stdout.flush()

        # get a solved state
        m = slvr.model()
        state0 = m[ostate0].as_long()
        state1 = m[ostate1].as_long()

        generated = []
        # generate random numbers from recovered state
        #xxx
        #for idx in xrange(15):
        for idx in xrange(200):
            if browser == 'chrome':
                state0, state1, out = xs128p_backward(state0, state1)
            else:
                state0, state1, out = xs128p(state0, state1)

            double = to_double(browser, out)
            generated.append(double)
            
        # use generated numbers to predict powerball numbers
        #xxx
        # power_ball(generated, browser)
        resultado_str_hex = ''
        for d in generated:
            estimado = struct.unpack('<Q', struct.pack('d', d + 1))[0] & 0xFFFFFFFF00000
            resultado_str_hex = resultado_str_hex + hex(estimado).replace('00000L', '').replace('0x', '')        
        print 'siguientes 200x4bytes estimados: ' + resultado_str_hex
        print
        print 'encontrados siguientes 8bytes generados en browser? ' + str(sig_8b_hex in resultado_str_hex)
        print 'encontrados siguientes 16bytes generados en browser? ' + str(sig_16b_hex in resultado_str_hex)

    else:
        print 'UNSAT'

main()
