section .bss
    buffer resb 100

section .data
    success_msg db "REDFOX{Obviously_This_Is_Real_Flag}", 0xA
    success_len equ $ - success_msg

section .text
    global _start

    _start:
        mov rax, 0      
        mov rdi, 0      
        mov rsi, buffer 
        mov rdx, 100    
        syscall

       
        mov rsi, buffer 
        mov rcx, rax     
        dec rcx        

    check_loop:
        cmp rcx, 0
        je end_program  
        mov al, [rsi]  
        cmp al, 0x7E   
        je okie     
        inc rsi         
        dec rcx         
        jmp check_loop  

    okie:
        mov rax, 1           
        mov rdi, 1          
        mov rsi, success_msg 
        mov rdx, success_len 
        syscall

    end_program:
        mov rax, 60 
        xor rdi, rdi 
        syscall