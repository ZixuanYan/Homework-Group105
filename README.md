# 实验名称

**SM2**

# 实验内容

1.  Project11：实现SM2加密算法
2.  Project13：在椭圆曲线上实现多集合哈希
3.  Project14：SM2 PGP
4.  Project15：实现SM2 2p签名与真实网络通信
5.  Project16：实现SM2 2p解密与真实网络通信
6.  Project12：用概念验证代码测试SM2签名存在的漏洞

# 作者

姓名：闫子轩

组号：Group105

学号：202100460160

Github账户地址：https://github.com/ZixuanYan

# 软件环境

编译器：Python 3.10，Visual Studio 2019

# SM2实现

## SM2

SM2算法是中国国家密码局推出的国产化算法，是基于椭圆曲线离散对数问题的难解性而构建的，相对于RSA算法，SM2具有密钥更小，运算速度更快，相同密钥长度下具有更高安全性等优势。

## GmSSL

GmSSL是一个开源的加密包的python实现，支持SM2/SM3/SM4等国密(国家商用密码)算法、项目采用对商业应用友好的类BSD开源许可证，开源且可以用于闭源的商业应用，实现SM2首先需要导入该库:

`pip install gmssl`

## 算法逻辑

### 获取公私钥

椭圆曲线方程：$y^2 = x^3+ax+b \mod p$

1.  确认a、b、p，确认曲线
2.  选择一个点P$( x_{g},y_{g} )$为基点
3.  对曲线做切线、x对称点运行。次数为d,运算倍点为Q
4.  d为私钥，Q为公钥

### 密钥对的生成

1.  产生随机整数d\[1,n-2\]
2.  G为基点，计算点$P=(xP,yP)=[d]G$
3.  密钥对为:(d,P)其中，d为私钥，P为公钥

### 加密算法

M为明文字符串

1.  获取随机数k
2.  $(x1,y1)=[k]G$
3.  $S=[h]P$ ，h为余因子
4.  $C1=(x2,y2)=[k]P$
5.  $t=KDF(x2∥y2,klen)$，klen为M的长度，KDF是sm2的密钥派生函数
6.  $C2=M+t$
7.  $C3=Hash(x2∥M∥y2)$
8.  $C=C1∥C2∥C3$

### 解密算法

C为密文字符串,klen为密文中C2的长度

1.  C1=C里面获取，验证C1是否满足椭圆曲线。C2长度确定，可以获取C1内容。
2.  $S=[h]C1$，S为无穷点，退出
3.  $(x2,y2)=[d]C1$
4.  $t=KDF(m2∥y2,klen)$
5.  $\widetilde M=C2+t$
6.  $u=Hash(x2∥ \widetilde M∥y2),u ?= C3$
7.  $\widetilde M$为明文

## 运行结果

输入需要加密的信息：“SDUYZX”，得到以下结果： 
![](https://zx777-1319535985.cos.ap-beijing.myqcloud.com/20230727153323.png)

# 在椭圆曲线上实现多集合哈希
## ECMH
ECMH整体思路是：先把集合里的元素映射成椭圆曲线上的点，然后利用椭圆曲线上的加法求解哈希值。

为达到相同的安全性，ECMH算法需要的密钥长度远远小于哈希求和算法，因而ECMH相较哈希求和算法更为安全。
## 实现思路
- 定义一个椭圆曲线的参数 p、a、b、n，并给定了一个基点 G 的坐标。
- 调用 keygen(a, p, n, G) 生成密钥对，其中私钥 d 是随机生成的，公钥 k 是私钥对应的基点乘法。
- 调用 _hash(s) 对输入的字节串列表 s 进行哈希运算，得到哈希值 r。
- 打印私钥、公钥、输入和哈希值的结果。
## 运行结果
![](https://zx777-1319535985.cos.ap-beijing.myqcloud.com/20230801143018.png)
# SM2 PGP
## PGP简要介绍
PGP(Pretty Good Privacy)，是一个基于RSA公钥和对称加密相结合的邮件加密软件。该系统能为电子邮件和文件存储应用过程提供认证业务和保密业务。

PGP是个混合加密算法，它由一个对称加密算法、一个非对称加密算法、与单向散列算法以及一个随机数产生器（从用户击键频率产生伪随机数序列的种子）组成。

## 具体实现
本次实验旨在实现一个简易PGP，调用GMSSL库中封装好的SM2/SM4加解密函数。
加密时使用对称加密算法SM4加密消息，非对称加密算法SM2加密会话密钥；
解密时先使用SM2解密求得会话密钥，再通过SM4和会话密钥求解原消息。

**加密：**

![](https://zx777-1319535985.cos.ap-beijing.myqcloud.com/20230803200030.png)

**解密：**

![](https://zx777-1319535985.cos.ap-beijing.myqcloud.com/20230803200340.png)

## 运行结果
输入要加密的信息：“SDUYZX”，得到如下结果：

![](https://zx777-1319535985.cos.ap-beijing.myqcloud.com/20230803201606.png)
# 实现SM2 2p签名与真实网络通信
## 实现原理
![](https://zx777-1319535985.cos.ap-beijing.myqcloud.com/20230803215326.png)

## 运行结果
首先运行2P_sign_client2,而后运行2P_sign_client1.

![](https://zx777-1319535985.cos.ap-beijing.myqcloud.com/20230804094317.png)

![](https://zx777-1319535985.cos.ap-beijing.myqcloud.com/20230804094358.png)
# 实现SM2 2p解密与真实网络通信
## 实验原理
![](https://zx777-1319535985.cos.ap-beijing.myqcloud.com/20230804104636.png)
## 运行结果
首先运行2P_dec_client2,而后运行2P_dec_client1.

![](https://zx777-1319535985.cos.ap-beijing.myqcloud.com/20230804103600.png)

![](https://zx777-1319535985.cos.ap-beijing.myqcloud.com/20230804103644.png)
# 用概念验证代码测试SM2签名存在的漏洞
## 可能存在的漏洞
### k泄露
![](https://zx777-1319535985.cos.ap-beijing.myqcloud.com/20230801133104.png)

首先给定一个消息m，使用SM2签名算法对其进行签名，计算得到签名结果(r, s)。
然后通过逆运算，根据公式 (inverse(s + r,n) * (k - s))%n 推导出私钥$d_A$。
最后打印输出私钥$d_A$。

在签名过程中，短暂泄露了签名所使用的随机数k。通过知道签名结果(r, s)，通过简单的逆推运算就可以恢复出私钥sk。这个过程显然是不安全的，因为私钥的泄露会导致签名无效，并且攻击者可以进一步利用私钥进行其他的恶意操作。
### k重用
![](https://zx777-1319535985.cos.ap-beijing.myqcloud.com/20230801133755.png)

给定两个不同的消息m1和m2，分别使用SM2签名算法对其进行签名，计算得到签名结果(r1, s1)和(r2, s2)。
然后通过逆运算，根据公式 ((s2 - s1) * inverse((s1 - s2 + r1 - r2),n))%n 推导出私钥$d_A$。
最后打印输出私钥$d_A$。

如果在两个不同的消息上使用相同的随机数k进行签名，那么通过简单的逆推运算，可以推导出私钥$d_A$。这个过程同样是不安全的，因为私钥的重用会导致签名无效，并且攻击者可以通过观察多个签名结果来进一步推导出私钥。

### 多个用户重用k
![](https://zx777-1319535985.cos.ap-beijing.myqcloud.com/20230801134119.png)

给定两个不同的消息m1和m2，分别由两个不同的用户使用SM2签名算法对其进行签名，计算得到签名结果(r1, s1)和(r2, s2)。
然后通过逆运算，根据公式 ((k - s1) * inverse(s1 + r1,n))%n 和 ((k - s2) * inverse(s2 + r2,n))%n 分别推导出用户1和用户2的私钥$d_A$和$d_B$。

如果在不同的用户之间重用相同的随机数k进行签名，那么通过逆推运算，每个用户都能推导出相应的私钥。这种方式同样是不安全的，因为私钥的重用会导致签名无效，并且攻击者可以通过观察不同用户的签名结果来进一步推导出私钥。

### 使用和ECDSA相同的d与k

![](https://zx777-1319535985.cos.ap-beijing.myqcloud.com/20230801134649.png)

给定一个消息m，分别使用SM2签名算法和ECDSA签名算法对其进行签名，计算得到签名结果(r1, s1)和(r2, s2)。
然后通过逆运算，根据公式 ((s1 * s2 - e1) * inverse((r1 - s1 * s2 - s1 * r2),n))%n 推导出私钥sk。

如果使用相同的随机数k和系数d进行签名，通过逆推运算，可以推导出私钥sk。然而，私钥和随机数的重用会破坏密码学的安全性，攻击者可以通过观察多个签名结果来推导出私钥。并且使用相同的随机数k也会导致签名无效。

## 运行结果
![](https://zx777-1319535985.cos.ap-beijing.myqcloud.com/20230801140051.png)
