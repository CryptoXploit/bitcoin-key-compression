import json
import urllib2
import time
import sys
from colorama import init
init()

from colorama import Fore, Back, Style
def rscan(addr):
	"""Check address for duplicated r values."""
	# TODO: add BCI API check address

	print "ADDRESS-R-SCAN: "
	
	urladdr = 'https://blockchain.info/address/%s?format=json&offset=%s'


	addrdata = json.load(urllib2.urlopen(urladdr % (addr, '0')))
	ntx = addrdata['n_tx']
	print (Fore.CYAN + "Data for pubkey: " + str(addr) + " has " + str(addrdata['n_tx']).center(6) + "Tx%s" % 's'[ntx==1:])
	#print "number of txs: " + str(addrdata['n_tx'])


	txs = []
	for i in range(0, ntx//50 + 1):
		sys.stderr.write("\nFetching Txs from offset\t%s\n" % str(i*50))
		jdata = json.load(urllib2.urlopen(urladdr % (addr, str(i*50))))
		txs.extend(jdata['txs'])	

	assert len(txs) == ntx
	addrdata['txs'] = txs


	y = 0
	inputs = []
	while y < ntx:	
		zy = 0
		while zy < addrdata['txs'][y]['vin_sz']:
			inputs.append(addrdata['txs'][y]['inputs'][zy]['script'])
			zy += 1
		y += 1

	xi = 0
	zi = 1
	lenx = len(inputs)
	alert = 0
	
	bad = []
	while xi < lenx-1:
		x = 0
		while x < lenx-zi:
			if inputs[xi][10:74] == inputs[x+zi][10:74]:
				print (Fore.RED + "\nVulnerable Resued R-Value: ")
				print(Style.RESET_ALL)
				print inputs[x+zi][10:74]
				bad.append((int(x), str(inputs[x+zi][10:74])))
				alert += 1
			x += 1
			zi += 1
		xi += 1


	if alert < 1:
		print (Fore.GREEN +"\n\n======================Good pubKey. Not vulnerable=========================.")
		print(Style.RESET_ALL)
	else:
		print (Fore.RED + "Address %s has %d reused R value%s!" % (addr, len(bad), "s"[len(bad)==1:]))
		return bad
		print(Style.RESET_ALL)
if __name__ == '__main__':
	from sys import argv
	print (Fore.YELLOW + """SCAN ADDR""")
	if len(argv) == 1:
		addr = raw_input("type address:  ")
	elif len(argv) == 2 and isinstance(argv[1], basestring):
		addr = str(argv[1])
	rscan(addr)
	
