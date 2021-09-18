from pwn import *
from pprint import pprint

elf = ELF("./babyrop")
pprint(elf.got)

pprint(elf.plt)
