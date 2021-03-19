import bitcoin
import hashlib
import txnUtils
import keyUtils

tx = "01000000036141525fc24792da81f8213912d1e478e326c1846c33c2335cb98bba6019e823010000008c49304602210090389f97d71d1426a7c66d1ce5c6ac421095c86e94aa3b9fb15f136d032f3c31022100d8abb034a1cdf0d8113e00f079b352bdf526b849f44a00124542689bad48871e01410429f32b89e3646f27f815e110ecace0774d7b290b1e0b6d7014c31ca031ca7fddc807706b6ccb4bef11c3aa3ac23066fe4a8423a8a1e68aa6acc6ee5daf8f627efffffffffd2acb31adba9b763e001cab424f120a96b18fb4b629585b79b844702a12028600000000fdfd0000483045022100dfcfafcea73d83e1c54d444a19fb30d17317f922c19e2ff92dcda65ad09cba24022001e7a805c5672c49b222c5f2f1e67bb01f87215fb69df184e7c16f66c1f87c290347304402204a657ab8358a2edb8fd5ed8a45f846989a43655d2e8f80566b385b8f5a70dab402207362f870ce40f942437d43b6b99343419b14fb18fa69bee801d696a39b3410b8034c695221023927b5cd7facefa7b85d02f73d1e1632b3aaf8dd15d4f9f359e37e39f05611962103d2c0e82979b8aba4591fe39cffbf255b3b9c67b3d24f94de79c5013420c67b802103ec010970aae2e3d75eef0b44eaa31d7a0d13392513cd0614ff1c136b3b1020df53aeffffffff86072db8307673a8a63d4bf4e133f90d513f47c3e25c512e1aff8cfd892799bd00000000fdfd0000483045022100dfcfafcea73d83e1c54d444a19fb30d17317f922c19e2ff92dcda65ad09cba24022001e7a805c5672c49b222c5f2f1e67bb01f87215fb69df184e7c16f66c1f87c290347304402204a657ab8358a2edb8fd5ed8a45f846989a43655d2e8f80566b385b8f5a70dab402207362f870ce40f942437d43b6b99343419b14fb18fa69bee801d696a39b3410b8034c695221023927b5cd7facefa7b85d02f73d1e1632b3aaf8dd15d4f9f359e37e39f05611962103d2c0e82979b8aba4591fe39cffbf255b3b9c67b3d24f94de79c5013420c67b802103ec010970aae2e3d75eef0b44eaa31d7a0d13392513cd0614ff1c136b3b1020df53aeffffffff01600d5b00000000001976a914db1dc9719a137e0661825dae080ecf3f7a05390688ac00000000"

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


