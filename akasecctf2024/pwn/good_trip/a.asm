section .data
    msg db "Hello, World!", 0

section .text
    global _start

_start:
    ; Load the address of the memory location into rdi
    mov rdi, msg

    ; Write "Hello, World!" to the memory location
    mov rax , 0x0f04000000000000
    add rax , 0x0001000000000000 
    mov qword [rdi], rax

    ; Exit the program
    mov rax, 60         ; syscall number for exit
    xor edi, edi 
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    syscall

