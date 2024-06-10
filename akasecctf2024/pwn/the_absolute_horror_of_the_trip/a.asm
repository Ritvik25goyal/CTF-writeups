section .text
    global _start

_start:
    ; Read FS base address into RAX
    mov rax,fs

    ; Exit the program
    mov rdi, 0           ; Exit code 0
    mov rax, 60          ; syscall: exit
    syscall
