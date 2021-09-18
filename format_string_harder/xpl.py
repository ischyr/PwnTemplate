from pwn import *
#context_level='DEBUG'

p = process("./armoury")
elf = ELF("./armoury", checksec=False)

def main():

	#8 ?

	p.interactive()

if __name__=="__main__":
	main()
