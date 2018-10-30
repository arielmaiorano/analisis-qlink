import math
import struct
import random
#sys.path.append('/home/dgoddard/tools/z3/build')
from z3 import *
import binascii

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
        impl = Implies(condition, (calc & 0xFFFFFFFFFFFFF) == int(generated))
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

# Print 'last seen' random number
#   and winning numbers following that.
# This was for debugging. We know that Math.random()
#   is called in the browser zero times (updated) for each page click 
#   in Chrome and once for each page click in Firefox.
#   Since we have to click once to enter the numbers
#   and once for Play, we indicate the winning numbers
#   with an arrow.
def power_ball(generated, browser):
    # for each random number (skip 4 of 5 that we generated)
    for idx in xrange(len(generated[4:])):
        # powerball range is 1 to 69
        poss = range(1, 70)
        # base index 4 to skip
        gen = generated[4+idx:]
        # get 'last seen' number
        g0 = gen[0]
        gen = gen[1:]
        # make sure we have enough numbers 
        if len(gen) < 6:
            break
        print g0

        # generate 5 winning numbers
        nums = []
        for jdx in xrange(5):
            index = int(gen[jdx] * len(poss))
            val = poss[index]
            poss = poss[:index] + poss[index+1:]
            nums.append(val)

        # print indicator
        if idx == 0 and browser == 'chrome':
            print '--->',
        elif idx == 2 and browser == 'firefox':
            print '--->',
        else:
            print '    ', 
        # print winning numbers
        print sorted(nums),

        # generate / print power number or w/e it's called
        double = gen[5]
        val = int(math.floor(double * 26) + 1)
        print val

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
    dubs = [0.6498194402314823, 0.12224013625507735, 0.4930168331608864]
    dubs = [0.4216013899213702, 0.8806982113940351, 0.15953025831637024, 0.46120940659774257, 0.7778432929519106]
    dubs = [0.17394703352942642, 0.655302381013863, 0.46517598891209655, 0.5330260071330031]
    # 562ecc7d5787c4257a15730255aa1995


# [0.5330260071330031, 0.46517598891209655, 0.655302381013863, 0.17394703352942642]
# [0.3419153777791868, 0.47688978967710405, 0.3346267690752802, 0.1498924980395373, 0.9772307755110838, 0.277759963648736, 0.3490057374202118, 0.5835660107206009, 0.9968832470448943, 0.9646066938212405, 0.20857378715243535, 0.8024843273171751, 0.28840919791093156, 0.006909421458177301, 0.9764454080416469]
    
    #4294967296
    #0.47688978967710405 * 2**32 =
    # 2048226050.4594802947391488
    # 2048226050 = 7a157302
    # 2048226050 / 2**32 =
    # 0.4768897895701229572296142578125
    # 0.476889789-67710405
    

    # a = 0.4768897895701229572296142578125
    # b = 0.47688978967710405
    # c = 0.476889789
    # d = ((c * 0x100000000))

    
    # x = struct.unpack('<Q', struct.pack('d', a + 1))[0] & 0xFFFFFFFFFFFFF 
    # print hex(x)
    # x = struct.unpack('<Q', struct.pack('d', b + 1))[0] & 0xFFFFFFFFFFFFF 
    # print hex(x)
    # x = struct.unpack('<Q', struct.pack('d', c + 1))[0] & 0xFFFFFFFFFFFFF 
    # print hex(x)
    # x = struct.unpack('<Q', struct.pack('d', d + 1))[0] & 0xFFFFFFFFFFFFF 
    # print hex(x)

    a = 0.037094129539806175
    b = 0.04068012111417274
    c = 0.020835041220406803
    d = 0.11798809512917008
    
    # x1 = struct.unpack('<Q', struct.pack('d', a + 1))[0] & 0xFFFFFFFF
    # print hex(x1)
    # x2 = struct.unpack('<Q', struct.pack('d', b + 1))[0] & 0xFFFFFFFF
    # print hex(x2)
    # x3 = struct.unpack('<Q', struct.pack('d', c + 1))[0] & 0xFFFFFFFF
    # print hex(x3)
    # x4 = struct.unpack('<Q', struct.pack('d', d + 1))[0] & 0xFFFFFFFF
    # print hex(x4)

    x1 = struct.unpack('<Q', struct.pack('d', a + 1))[0] & 0xFFFFFFFFFFFFF
    print hex(x1)
    x2 = struct.unpack('<Q', struct.pack('d', b + 1))[0] & 0xFFFFFFFFFFFFF
    print hex(x2)
    x3 = struct.unpack('<Q', struct.pack('d', c + 1))[0] & 0xFFFFFFFFFFFFF
    print hex(x3)
    x4 = struct.unpack('<Q', struct.pack('d', d + 1))[0] & 0xFFFFFFFFFFFFF
    print hex(x4)
    
    print hex(x1).replace("0x", "").replace("L", "") + hex(x3).replace("0x", "").replace("L", "") + hex(x2).replace("0x", "").replace("L", "") + hex(x4).replace("0x", "").replace("L", "")
    
#0.037094129539806175
#0.04068012111417274
#0.020835041220406803
#0.11798809512917008
#097f00390a6a032d055571fc1e3477c1

#0x97f00393f3f0L
#0xa6a032dc85e7L
#0x55571fca7079L
#0x1e3477c1e5a9dL
#97f00393f3f055571fca7079a6a032dc85e71e3477c1e5a9d

    iv_hex = '097f00390a6a032d055571fc1e3477c1'
    iv_words = [0, 0, 0, 0]
    for i in range(4):
        ii = i * 8
        #iv_words[i] = int(iv_hex[ii:ii+8], 16) << 1 # & 0xFFFFFFFFFFFFF
        #iv_words[i] = struct.unpack('<Q', binascii.unhexlify(iv_hex[ii:ii+8]) << 1)[0] & 0xFFFFFFFFFFFFF
        iv_words[i] = int(iv_hex[ii:ii+8] + '00000', 16) & 0xFFFFFFFFFFFFF
        print hex(iv_words[i])
BROWSER: chrome
0x97f00393f3f0L
0x97f003900000L

0xa6a032dc85e7L
0xa6a032d00000L

0x55571fca7079L
0x55571fc00000L

0x1e3477c1e5a9dL
0x1e3477c100000L
    
    print type(x1)
    print type(iv_words[i])
    
    sys.stdout.flush()

    a = 1/0
    

    dubs = [0.17394703, 0.65530238, 0.46517598]
    
    
    if browser == 'chrome':
        dubs = dubs[::-1]

    print dubs


    # from the doubles, generate known piece of the original uint64 
    generated = []
    for idx in xrange(3):
        if browser == 'chrome':
            recovered = struct.unpack('<Q', struct.pack('d', dubs[idx] + 1))[0] & 0xFFFFFFFFFFFFF 
        elif browser == 'firefox':
            recovered = dubs[idx] * (0x1 << 53) 
        elif browser == 'safari':
            recovered = dubs[idx] / (1.0 / (1 << 53))
        generated.append(recovered)

    # setup symbolic state for xorshift128+
    ostate0, ostate1 = BitVecs('ostate0 ostate1', 64)
    sym_state0 = ostate0
    sym_state1 = ostate1
    slvr = Solver()
    conditions = []

    # run symbolic xorshift128+ algorithm for three iterations
    # using the recovered numbers as constraints
    for ea in xrange(3):
        sym_state0, sym_state1, ret_conditions = sym_xs128p(slvr, sym_state0, sym_state1, generated[ea], browser)
        conditions += ret_conditions

    if slvr.check(conditions) == sat:
        # get a solved state
        m = slvr.model()
        state0 = m[ostate0].as_long()
        state1 = m[ostate1].as_long()

        generated = []
        # generate random numbers from recovered state
        for idx in xrange(15):
            if browser == 'chrome':
                state0, state1, out = xs128p_backward(state0, state1)
            else:
                state0, state1, out = xs128p(state0, state1)

            double = to_double(browser, out)
            generated.append(double)

        print generated
        
        # use generated numbers to predict powerball numbers
        power_ball(generated, browser)
    else:
        print 'UNSAT'

main()
