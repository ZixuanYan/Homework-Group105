# 导入必要的库
import math
import socket
from gmpy2 import invert
from random import randint
from os.path import commonprefix

# 椭圆曲线参数
p = 0x8542D69E4C044F18E8B92435BF6FF7DE457283915C45517D722EDB8B08F1DFC3
a = 0x787968B4FA32C3FD2417842E73BBFEFF2F3C848B6831D7E0EC65228B3937E498
b = 0x63E4C6D3B23B0C849CF84241484BFE48F61D59A5B16BA06E6E12D1DA27C5249A
n = 0x8542D69E4C044F18E8B92435BF6FF7DD297720630485628D5AE74EE7C32E79B7
x = 0x421DEBD61B62EAB6746434EBC3CC315E32220B3BADD50BDC4C4E6C147FEDD43D
y = 0x0680512BCBB42C07D47349D2153B70C4E5D7FDFCBFA36EA1A85841B9E46E09A2

# 椭圆曲线上的加法(x, y) = (x1 + x2, y1 + y2)
def epoint_add(x1, y1, x2, y2):
    if x1 == x2 and y1 == p - y2:
        return False
    if x1 != x2:
        r = ((y2 - y1) * invert(x2 - x1, p)) % p  # invert函数用于求模逆
    else:
        r = (((3 * x1 * x1 + a) % p) * invert(2 * y1, p)) % p

    x = (r * -x1 - x2) % p
    y = (r * (x1 - x) - y1) % p
    return x, y

# 椭圆曲线上的点乘k * (x, y)
def epoint_mult(x, y, k):
    k = k % p
    k = bin(k)[2:]
    rx, ry = x, y
    for i in range(1, len(k)):
        rx, ry = epoint_add(rx, ry, rx, ry)
        if k[i] == '1':
            rx, ry = epoint_add(rx, ry, x, y)
    return rx % p, ry % p

# 设置TCP/IP服务器
HOST = ''
PORT = 1234
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.bind((HOST, PORT))

print("Client 2 connected!")

# 生成子私钥 d2
d2 = 0x5E35D7D3F3C54DBAC72E61819E730B019A84208CA3A35E4C2E353DFCCB2A3B53

# 从客户端1接收到T1
x, addr = s.recvfrom(1024)
x = int(x.decode(), 16)
y, addr = s.recvfrom(1024)
y = int(y.decode(), 16)
T1 = (x, y)

# 计算T2 = d2^(-1) * T1
T2 = epoint_mult(x, y, invert(d2, p))
x, y = hex(T2[0]), hex(T2[1])

s.sendto(x.encode('utf-8'), addr)
s.sendto(y.encode('utf-8'), addr)

print("Closed!")
