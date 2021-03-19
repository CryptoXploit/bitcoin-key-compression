import bitcoin
import hashlib
import txnUtils
import keyUtils

tx = "01000000013c10dccdd96187ec065a2404a829be91ccb2a80ee7986d4cbbb31cd493f69e5d000000006c493046022100c9f051042467433b2199526db1ba327154d2bcd7c90c40070ba06869c5512194022100b1146f90fac7ed0db71d2f0c91f30c51d11310c508a64719dc424cdf710cb38b012102545d2c25b98ec8827f2d9bee22b7a9fb98091b2008bc45b3b806d44624dc038cffffffff0200c5015a020000001976a914f507b67f6af2dcc993f6958c05855f4861cefe8888acc427e9254f0600001976a914b3dd79fb3460c7b0d0bbb8d2ed93436b88b6d89c88ac00000000"

m = txnUtils.parseTxn(tx)
e = txnUtils.getSignableTxn(m)
z = hashlib.sha256(hashlib.sha256(e.decode('hex')).digest()).digest()
z1 = z[::-1].encode('hex_codec')
z = z.encode('hex_codec')
s = keyUtils.derSigToHexSig(m[1][:-2])
pub =  m[2]
sigR = s[:64]
sigS = s[-64:]
sigZ = z
print ('Signed TX is :', tx)
print ('Signature (r, s pair) is :', s)
print ('Public Key is :', pub)
print ("")
print ("#################################################################################################")
print ("")
print ('Unsigned TX is :', e)
print ('hash of message (sigZ) is USE This ONE :', z)
print ('reversed z :', z1)
print ("")
print ("#################################################################################################")
print ("##################################VALUES NEEDED ARE BELOW #######################################")
print ("#################################################################################################")
print ("")
print ('THE R VALUE is  :', sigR)
print ('THE S VALUE is  :', sigS)
print ('THE Z VALUE is  :', sigZ)
print ('THE PUBKEY is :', pub)
