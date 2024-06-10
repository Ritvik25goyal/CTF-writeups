section .data
    some_value dq 0x12345678ABCDEF00 ; Example value
    some_ptr   dq some_value

section .text
    global _start

_start:
    ; Step 1: Load the pointer into rbx
    mov rbx, 0x1234567812345678 

    ; Step 2: Store the contents of rax into the memory location pointed to by rbx
    mov [rbx], rax

    ; Step 3: Clear the next 4 bytes at the memory location rbx + 4
    mov dword [rbx], 0

    ; Step 4: Set those 4 bytes to some value
    mov dword [rbx], 0x87654321

    ; Step 5: Load the contents of the memory location pointed to by rbx back into rbx
    mov rbx, [rbx]

    ; For demonstration, move RBX to RAX for observation
    mov rax, rbx

    ; Exit the program
    mov rdi, 0          ; Exit code 0
    mov rax, 60         ; syscall: exit
    syscall

