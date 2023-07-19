import random
import string
import math
import time

# 初始化向量 IV
IV = [0x7380166F, 0x4914B2B9, 0x172442D7, 0xDA8A0600,
      0xA96F30BC, 0x163138AA, 0xE38DEE4D, 0xB0FB0E4E]

# 左移函数
def leftshift(s,l):
    l = l % 32
    return (((s << l) & 0xFFFFFFFF) | ((s & 0xFFFFFFFF) >> (32-l)))

# 轮函数 FF
def FF(s1,s2,s3,i):
    if i>=0 and i<=15:
        return s1 ^ s2 ^ s3
    else:
        return ((s1 & s2) | (s1 & s3) | (s2 & s3))
    
# 轮函数 GG
def GG(s1,s2,s3,i):
    if i>=0 and i<=15:
        return s1 ^ s2 ^ s3
    else:
        return ((s1 & s2) | (~s1 & s3))
    
# 置换函数 P0
def P0(s):
    return s^leftshift(s,9)^leftshift(s,17)

# 置换函数 P1
def P1(s):
    return s^leftshift(s,15)^leftshift(s,23)

# 常量函数 T
def T(i):
    if i>=0 and i<=15:
        return 0x79cc4519
    else:
        return 0x7a879d8a
    
# 消息填充函数
def padding(message):
    m = bin(int(message,16))[2:]
    if len(m) != len(message)*4:
        m = '0'*(len(message)*4-len(m)) + m
    l = len(m)
    l_bin = '0'*(64-len(bin(l)[2:])) + bin(l)[2:]
    m = m + '1'
    m = m + '0'*(448-len(m)%512) + l_bin
    m = hex(int(m,2))[2:]
    return m

# 分块函数
def block(m):
    n = len(m)/128
    M = []
    for i in range(int(n)):
        M.append(m[0+128*i:128+128*i])
    return M

# 消息扩展函数
def message_extension(M,n):
    W = []
    W1 = []
    for j in range(16):
        W.append(int(M[n][0+8*j:8+8*j],16))
    for j in range(16,68):
        W.append(P1(W[j-16]^W[j-9]^leftshift(W[j-3],15))^leftshift(W[j-13],7)^W[j-6])
    for j in range(64):
        W1.append(W[j]^W[j+4])
    s1 = ''
    s2 = ''
    for x in W:
        s1 += (hex(x)[2:] + ' ')
    for x in W1:
        s2 += (hex(x)[2:] + ' ')
    return W,W1

# 消息压缩函数
def message_compress(V,M,i):
    A,B,C,D,E,F,G,H = V[i]
    W,W1 = message_extension(M,i)
    for j in range(64):
        SS1 = leftshift((leftshift(A,12)+E+leftshift(T(j),j%32))%(2**32),7)
        SS2 = SS1 ^ leftshift(A,12)
        TT1 = (FF(A,B,C,j)+D+SS2+W1[j])%(2**32)
        TT2 = (GG(E,F,G,j)+H+SS1+W[j])%(2**32)
        D = C
        C = leftshift(B,9)
        B = A
        A = TT1
        H = G
        G = leftshift(F,19)
        F = E
        E = P0(TT2)

    a,b,c,d,e,f,g,h = V[i]
    V1 = [a^A,b^B,c^C,d^D,e^E,f^F,g^G,h^H]
    return V1

# SM3 哈希算法
def SM3(M,IV):
    n = len(M)
    V = []
    V.append(IV)
    for i in range(n):
        V.append(message_compress(V,M,i))
    return V[n]

# 生成指定数量随机数的函数
def randomnum(n):
    rn = []
    while len(rn) < n:
        i = random.randint(0, pow(2,64))
        if i not in rn:
            rn.append(i)
    return rn

# 长度扩展攻击函数
def lengthextension_attack(m,IV,n):
    for i in range(n):
        m = '0' + m
    M = padding(m)
    M1 = block(M)
    h = SM3(M1,IV)
    return h

random_value = []
r1 = '20220430'
r2 = '20220601'
m = padding(r1)
M = block(m)
t = SM3(M,IV)
h1 = ""
for k in t:
    h1 += hex(k)[2:]
random_value.append(h1)

m1 = padding(m + r2)
M1 = block(m1)
t1 = SM3(M1,IV)
h2=""
for k in t1:
    h2 += hex(k)[2:]
random_value.append(h2)

t2 = lengthextension_attack(r2,t,128)
h3 = ""
for k in t2:
    h3 += hex(k)[2:]
random_value.append(h3)

print("r1||padding||r2:")
print(m + r2)

print("\nh2:")
print(random_value[1])

print("\nh3:")
print(random_value[2])

if random_value[1]==random_value[2]:
    print("\n长度扩展攻击成功!")
