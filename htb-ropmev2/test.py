from pwn import *
from pprint import pprint

elf = ELF("./ropmev2")


pprint(elf.plt)
log.info("=======================================")
pprint(elf.got)
