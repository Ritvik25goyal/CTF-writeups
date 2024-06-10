section .data
    sh db "/bin/sh", 0

section .text
    global _start

_start:
    ; Load the address of the string "/bin/sh" into rdi (first argument to execve)
    mov rdi, sh
    mov rsp, 0
    mov rbp, 0 
	; Set up argv (pointer to null-terminated array of pointers to arguments)
    xor rsi, rsi   ; argv is NULL (no arguments)
    xor rdx, rdx   ; envp is NULL (no environment variables)

    ; Prepare the syscall for execve
    mov rax, 59    ; syscall number for execve
    syscall

    ; Exit the program if execve fails
    mov rax, 60    ; syscall number for exit
    xor rdi, rdi   ; exit status 0
    syscall

