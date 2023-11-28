section .text
	global _start
_start: 
	mov rax, 29400045130965551
	push rax
    mov rdi, rsp
    xor rsi, rsi
    xor rdx, rdx
    mov rax, 0x3b
    syscall
