import sha3

# https://ed25519.cr.yp.to/python/ed25519.py
# only changed expmod to use python's native pow function, which is much faster
import ed25519

q = ed25519.q

def sqroot(xx):
    I = ed25519.expmod(2,(q-1)/4,q)
    x = ed25519.expmod(xx,(q+3)/8,q)
    if (x*x - xx) % q != 0: 
        x = (x*I) % q
    if (x*x - xx) % q != 0: 
        print("no square root!")
    return x

# changed a little bit from hashToPointCN in mininero, removed unused code etc
def hashToPointCN(input):
    u = sha3.keccak_256(input).digest()
    u = byte2long_r(u) % ed25519.q

    sqrtm1 = sqroot(-1)
    A = 486662
    
    w = (2 * u * u + 1) % q
    xp = (w *  w - 2 * A * A * u * u) % q

    #like sqrt (w / x) although may have to check signs..
    #so, note that if a squareroot exists, then clearly a square exists..
    rx = ed25519.expmod(w * ed25519.inv(xp), (q+3)/8, q) 

    x = (rx**2 * xp) % q

    y = (2 * u * u  + 1 - x) % q #w - x, if y is zero, then x = w

    negative = False
    if (y != 0):
        y = (w + x) % q #checking if you got the negative square root.
        if (y != 0) :
            negative = True
        else :
            rx = rx * -1 * sqroot(-2 * A * (A + 2) ) % q
            negative = False
    else :
        #y was 0..
        rx = (rx * -1 * sqroot(2 * A * (A + 2) ) ) % q 
        
    if not negative:
        rx = (rx * u) % q
        z = (-2 * A * u * u)  % q
        sign = 0
    else:
        z = -1 * A
        x = x * sqrtm1 % q #..
        y = (w - x) % q 
        if (y != 0) :
            rx = rx * sqroot( -1 * sqrtm1 * A * (A + 2)) % q
        else :
            rx = rx * -1 * sqroot( sqrtm1 * A * (A + 2)) % q
        sign = 1
        
    #setsign
    if ( (rx % 2) != sign ):
        rx =  - (rx) % q 
    rz = (z + w) % q
    ry = (z - w) % q
    rx = rx * rz % q
    
    rzi = ed25519.inv(rz)
    rx = (rx * rzi) % q
    ry = (ry * rzi) % q
    P = [rx, ry]
    P = ed25519.scalarmult(P, 8)
    
    return P
    
def byte2long_r(s):
    res = 0
    n = 0
    for c in s:
        res = res | (ord(c) << n)
        n += 8
    return res

def sc_reduce32(s):
    n = byte2long_r(s)
    return n % ed25519.l
    
def main():
    # Verification code for the first non-coinbase transaction
    # https://xmrchain.net/search?value=beb76a82ea17400cd6d7f595f70e1667d2018ed8f5a78d1ce07484222618c3cd
    
    # key image
    I = ed25519.decodepoint("f254220bb50d901a5523eaed438af5d43f8c6d0e54ba0632eb539884f6b7c020".decode("hex"))

    prefixhash = "ccabefb57635c09cfe66af861f11e1a379cd0de0e030409ab3c26418cf302166".decode("hex")

    public_keys = [
        "de00acad5a0df1c52ef51637cb89ae1c991c877acf6152252529009d6e51adbc",
        "1b6367f72a1cdbc7a21aa37e0ab2155529e404c2efaadd72ca7702e42bc96640",
        "1e4f2708aa04f52d4607d98ba18bf0f87b5045ff74df71f45649975093d19a12",
        "d1468a64e2703489fcd7d759bb0ca2a93d4acbdda3aaa77c103f5eb4424ed6b9",
        "feca0b1c0266f02eed4fb19f97bc077171de836d5dcca99280367f9c94ed05e8",
        "3c65dd846c83fb48036cd978d4d40c35065de407d20df34234332e5db49c6fde"
        ]
        
    signatures = [
        "a9e1d89bc06b40e94ea9a26059efc7ba5b2de7ef7c139831ca62f3fe0bb252008f8c7ee810d3e1e06313edf2db362fc39431755779466b635f12f9f32e44470a",
        "3e85e08a28fcd90633efc94aa4ae39153dfaf661089d045521343a3d63e8da08d7916753c66aaebd4eefcfe8e58e5b3d266b752c9ca110749fa33fce7c442703",
        "86fcf2bed4f03dd5dadb2dc1fd4c505419f8217b9eaec07521f0d8963e104603c926745039cf38d31de6ed95ace8e8a451f5a36f818c151f517546d55ac0f500",
        "e54d07b30ea7452f2e93fa4f60bdb30d71a0a97f97eb121e662006780fbf69002228224a96bff37893d47ec3707b17383906c0cd7d9e7412b3e6c8ccf1419b09",
        "3c06c26f96e3453b424713cdc5c9575f81cda4e157052df11f4c40809edf420f88a3dd1f7909bbf77c8b184a933389094a88e480e900bcdbf6d1824742ee520f",
        "c0032e7d892a2b099b8c6edfd1123ce58a34458ee20cad676a7f7cfd80a28f0cb0888af88838310db372986bdcf9bfcae2324480ca7360d22bff21fb569a530e"
        ]

    # The description in the Cryptonote 2.0 white paper is _almost_ right, but the final hash is
    # H(m, L_0, R_0, L_1, R_1...) with L and R alternating, and NOT
    # H(m, L_0, L_1, ..., R_0, R_1, ...) as it claims
    
    hash_input = prefixhash
    chal_sum = 0
    
    for i in xrange(len(public_keys)):
        pub_i = ed25519.decodepoint(public_keys[i].decode("hex"))
        chal_i = byte2long_r(signatures[i].decode("hex")[0:32])
        resp_i = byte2long_r(signatures[i].decode("hex")[32:64])
        
        t1 = ed25519.scalarmult(ed25519.B, resp_i)
        t2 = ed25519.scalarmult(pub_i, chal_i)
        left = ed25519.edwards(t1, t2)
        hash_input += ed25519.encodepoint(left)
        
        t1 = ed25519.scalarmult(hashToPointCN(ed25519.encodepoint(pub_i)), resp_i)
        t2 = ed25519.scalarmult(I, chal_i)
        right = ed25519.edwards(t1, t2)
        hash_input += ed25519.encodepoint(right)
        
        chal_sum += chal_i
        
    h = sha3.keccak_256(hash_input).digest()
    target = sc_reduce32(h)
    if target == (chal_sum % ed25519.l):
        print "SIGNATURE VERIFIED OK"
    else:
        raise Exception("bad signature!")
        
if __name__ == "__main__":
    main()
