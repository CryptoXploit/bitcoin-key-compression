#!/usr/bin/python


#################################################################################
#                                                                               #
#.______               _______.  ______     ___      .__   __.                  #
#|   _  \             /       | /      |   /   \     |  \ |  |                  # 
#|  |_)  |    ______ |   (----`|  ,----'  /  ^  \    |   \|  |                  #
#|      /    |______| \   \    |  |      /  /_\  \   |  . `  |                  #
#|  |\  \----.    .----)   |   |  `----./  _____  \  |  |\   |                  #
#| _| `._____|    |_______/     \______/__/     \__\ |__| \__|  v0.1.2          #
#                                                                               #
#GNU PL - 2015 - ca333                                                          # 
#                                                                               #         
#USE AT OWN RISK!                                                               #
#################################################################################

import json
import urllib2
import time
import sys

from colorama import init
init()

from colorama import Fore, Back, Style

#for some reason blockchain.info api-chain is 59711 blocks short..
blockstart = 170399
blockstart += 59711
blockcount = urllib2.urlopen("https://blockchain.info/de/q/getblockcount").read()

print (Fore.YELLOW +"WELCOME TO R-scan v0.1.2!")

print "ADDRESS-R-SCAN: "
addr = raw_input("type address:  ")
urladdr = "https://blockchain.info/de/rawaddr/" + str(addr)
#control api-url
print urladdr 
addrdata = json.load(urllib2.urlopen(urladdr))
print "Data for pubkey: " + str(addr)
print(Style.RESET_ALL)
print (Fore.CYAN + "number of txs: " + str(addrdata['n_tx']))
print(Style.RESET_ALL)
#tx-details:
y = 0
inputs = []
while y < addrdata['n_tx']:	
	print (Fore.MAGENTA + "#################################################################################")
	print(Style.RESET_ALL)
	print "TX Number :" + str(y+1)
	print "hash: " + str(addrdata['txs'][y]['hash'])
	print "number of inputs: " + str(addrdata['txs'][y]['vin_sz'])
	#only if 
	#if addrdata['txs'][y]['vin_sz'] > 1:
	zy = 0
	while zy < addrdata['txs'][y]['vin_sz']:
		print "Input-ScriptNR " + str(zy+1) + " :" + str(addrdata['txs'][y]['inputs'][zy]['script'])
		inputs.append(addrdata['txs'][y]['inputs'][zy]['script'])
		zy += 1
	
	y += 1
	
print "compare: "

xi = 0
zi = 1
lenx = len(inputs)
alert = 0

#compare the sig values in each input script
while xi < lenx-1:
	x = 0
	while x < lenx-zi: 
		if inputs[xi][10:74] == inputs[x+zi][10:74]:
			print (Fore.RED + "In Input Number: " + str(xi) + "[global increment] " + str(inputs[xi]))
			print('\a')
                        print "Vulnerable Resued R-Value: "
			print inputs[x+zi][10:74]
                        alert += 1
                        print(Style.RESET_ALL)

		x += 1
		
	zi += 1
	xi += 1

#check duplicates
#alert when everything ok

if alert < 1:
	print (Fore.GREEN +"======================Good pubKey. Not vulnerable=========================")


sys.exit()
