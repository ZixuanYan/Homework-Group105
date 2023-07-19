import random
import string
import math
import time
from collections import Counter

IV = [0x7380166F, 0x4914B2B9, 0x172442D7, 0xDA8A0600,
      0xA96F30BC, 0x163138AA, 0xE38DEE4D, 0xB0FB0E4E]

def leftshift(s,l):
    l = l % 32
    return (((s << l) & 0xFFFFFFFF) | ((s & 0xFFFFFFFF) >> (32-l)))

def FF(s1,s2,s3,i):
    if i>=0 and i<=15:
        return s1 ^ s2 ^ s3
    else:
        return ((s1 & s2) | (s1 & s3) | (s2 & s3))
    
def GG(s1,s2,s3,i):
    if i>=0 and i<=15:
        return s1 ^ s2 ^ s3
    else:
        return ((s1 & s2) | (~s1 & s3))
    
def P0(s):
    return s^leftshift(s,9)^leftshift(s,17)

def P1(s):
    return s^leftshift(s,15)^leftshift(s,23)

def T(i):
    if i>=0 and i<=15:
        return 0x79cc4519
    else:
        return 0x7a879d8a
    
def padding(message):
    m = bin(int(message,16))[2:]  # 将输入的十六进制消息转换为二进制形式
    if len(m) != len(message)*4:  # 检查二进制消息的位数是否正确
        m = '0'*(len(message)*4-len(m)) + m  # 补齐位数
    l = len(m)
    l_bin = '0'*(64-len(bin(l)[2:])) + bin(l)[2:]  # 将消息的长度转换为二进制，并补齐位数
    m = m + '1'  # 在消息的末尾添加一个比特位'1'
    m = m + '0'*(448-len(m)%512) + l_bin  # 在消息的末尾补充0，使得消息总长度满足对512取余等于448的要求，并添加消息长度
    m = hex(int(m,2))[2:]  # 将二进制消息转换回十六进制形式
    return m

def block(m):
    n = len(m)/128
    M = []
    for i in range(int(n)):
        M.append(m[0+128*i:128+128*i])  # 将填充后的消息切分成128位的块
    return M

def message_extension(M,n):
    W = []
    W1 = []
    for j in range(16):
        W.append(int(M[n][0+8*j:8+8*j],16))  # 将块中的十六进制值转换为整数并存储到W中
    for j in range(16,68):
        W.append(P1(W[j-16]^W[j-9]^leftshift(W[j-3],15))^leftshift(W[j-13],7)^W[j-6])  # 进行消息扩展
    for j in range(64):
        W1.append(W[j]^W[j+4])  # 生成W1
    s1 = ''
    s2 = ''
    for x in W:
        s1 += (hex(x)[2:] + ' ')  # 将W转换为字符串形式
    for x in W1:
        s2 += (hex(x)[2:] + ' ')  # 将W1转换为字符串形式
    return W,W1

def message_compress(V,M,i):
    A,B,C,D,E,F,G,H = V[i]
    W,W1 = message_extension(M,i)  # 进行消息扩展
    for j in range(64):
        SS1 = leftshift((leftshift(A,12)+E+leftshift(T(j),j%32))%(2**32),7)  # 计算SS1
        SS2 = SS1 ^ leftshift(A,12)  # 计算SS2
        TT1 = (FF(A,B,C,j)+D+SS2+W1[j])%(2**32)  # 计算TT1
        TT2 = (GG(E,F,G,j)+H+SS1+W[j])%(2**32)  # 计算TT2
        D = C
        C = leftshift(B,9)
        B = A
        A = TT1
        H = G
        G = leftshift(F,19)
        F = E
        E = P0(TT2)

    a,b,c,d,e,f,g,h = V[i]
    V1 = [a^A,b^B,c^C,d^D,e^E,f^F,g^G,h^H]  # 更新状态V
    return V1

def SM3(M):
    n = len(M)
    V = []
    V.append(IV)  # 初始化状态V
    for i in range(n):
        V.append(message_compress(V,M,i))  # 进行消息压缩
    return V[n]  # 返回哈希结果

def rho_attack():
    random_value = []  # 存储已生成的随机值
    for i in range(pow(2,6)):
        r = random.randint(0, pow(2,64))  # 生成64位的随机数
        m = padding(str(r))  # 对随机数进行填充
        M = block(m)  # 将填充后的消息切分成128位块
        Mn = SM3(M)  # 对消息进行哈希运算
        tmp=""
        for k in Mn:
            tmp += hex(k)[2:]  # 将哈希结果转换为十六进制字符串
            
        t = tmp[:1]  # 提取哈希结果的第一个字节
        if(t in random_value):  # 判断该字节是否在已生成的随机值列表中出现过
            print("Rho攻击成功!")  # 攻击成功
            break
        else:
            random_value.append(t)
        
start = time.time()
rho_attack()  # 执行Rho攻击
end = time.time()
print("运行时间：%.3fs"%(end-start))  # 打印运行时间
