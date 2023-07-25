from AES import AES128

key = input("key = ")
plain = input("plain = ")
# cipher = input("cipher = ")
aesencrypt = AES128(key)
enc=aesencrypt.encrypto(plain)
print('密钥是：',key)
print('明文是：'+plain)
print('密文是：'+enc)
detext = aesencrypt.decrypto(enc)
print('原文是：',detext)
